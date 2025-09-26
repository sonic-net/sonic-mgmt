#!/usr/bin/env python3
"""
Azure OpenAI-Powered Flaky Failure Categorization and Analysis Script

This script analyzes flaky test cases from Sonic testing using Azure OpenAI APIs to:
1. Categorize failures based on their summary text using AI analysis
2. Select representative cases for each failure type
3. Ensure no duplicate representatives across different failure types
4. Output a curated list of real flaky issues

Requirements:
- Azure OpenAI service with deployed model (e.g., GPT-4)
- Environment variables: OPENAI_API_KEY, OPENAI_API_BASE, OPENAI_API_VERSION

Input: flaky_cases.csv
Output: CSV with columns: full_casename,subject,branch,failure_summary
"""

import pandas as pd
from openai import AzureOpenAI
import os
import json
import re
from collections import defaultdict
import time
from config import logger, configuration, AI_FLAKY_UNIQUE_SUMMARY_CSV, \
    AI_FLAKY_CATEGORIZED_CSV, AI_FLAKY_ANALYSIS_CSV, AI_FLAKY_AFTER_DEDUPLICATION_CSV, \
    AI_FLAKY_DUPLICATED_CSV, AI_FLAKY_FAILURES_DATA_CSV
import traceback


def convert_timestamps_to_strings(obj):
    """
    Recursively convert pandas Timestamp objects to strings in nested data structures.
    """
    if isinstance(obj, pd.Timestamp):
        return obj.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(obj, dict):
        return {key: convert_timestamps_to_strings(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_timestamps_to_strings(item) for item in obj]
    else:
        return obj


class LLMFailureCategorizer:
    def __init__(self):
        """
        Initialize the Azure OpenAI-based categorizer

        Args:
            chunk_size: Number of failures to process in each API call
            max_categories: Maximum number of failure categories to create
        """
        self.chunk_size = configuration["ai_analysis"]["chunk_size"]
        self.client = None
        self._initialize_llm_client()
        self.HOST_RE = re.compile(
            r'^(?:[A-Za-z0-9]*(?:str|bjw)[A-Za-z0-9]*)'  # first part must contain 'str' or 'bjw'
            r'-'                        # first hyphen
            r'(?:[A-Za-z0-9]+(?:x\d+)?)'  # platform: alnum+, optional x+digits
            r'(?:-[A-Za-z0-9]+)*'       # any additional segments, hyphen + alnum+
            r'-(?:u\d+|\d+)$'          # final hyphen + either 'u' followed by digits or just digits
        )

    def _initialize_llm_client(self):
        """
        Initialize the Azure OpenAI client using the new SDK interface
        """
        try:
            # Get Azure OpenAI configuration from environment variables
            openai_api_key = os.environ.get('AZURE_OPENAI_API')
            openai_endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
            openai_api_version = os.environ.get('AZURE_OPENAI_API_VERSION', '2025-01-01-preview')

            if not openai_api_key:
                logger.error("Azure OpenAI API key not found. Please set AZURE_OPENAI_API environment variable.")
                logger.info("Required environment variables for Azure OpenAI:")
                logger.info("  - AZURE_OPENAI_API: Your Azure OpenAI API key")
                logger.info("  - AZURE_OPENAI_ENDPOINT: Your Azure OpenAI endpoint")
                logger.info("    Example: https://your-resource-name.openai.azure.com/")
                logger.info("  - AZURE_OPENAI_API_VERSION: API version (default: 2025-01-01-preview)")
                logger.info("\nFor Azure OpenAI setup, see: Azure_OpenAI_Setup_Guide.md")
                raise ValueError("Azure OpenAI API key not configured")

            if not openai_endpoint:
                logger.error("Azure OpenAI endpoint not found. Please set AZURE_OPENAI_ENDPOINT environment variable.")
                logger.info("Example: https://your-resource-name.openai.azure.com/")
                raise ValueError("Azure OpenAI endpoint not configured")

            if (not openai_endpoint.lower().endswith('.openai.azure.com/') and
                    not openai_endpoint.lower().endswith('.openai.azure.com')):
                logger.error("Invalid Azure OpenAI endpoint format.")
                logger.info("Expected format: https://your-resource-name.openai.azure.com/")
                raise ValueError("Invalid Azure OpenAI endpoint")

            # Ensure endpoint ends with /
            if not openai_endpoint.endswith('/'):
                openai_endpoint += '/'

            # Initialize Azure OpenAI client with new SDK
            self.client = AzureOpenAI(
                api_key=openai_api_key,
                azure_endpoint=openai_endpoint,
                api_version=openai_api_version
            )

            logger.info("Configured for Azure OpenAI:")
            logger.info(f"  Endpoint: {openai_endpoint}")
            logger.info(f"  API Version: {openai_api_version}")
            logger.info(f"  Deployment: {configuration['ai_analysis']['deployment_name']}")
            logger.info("  Note: Make sure your deployment name is correct in Azure OpenAI Studio")

        except Exception as e:
            logger.error(f"Failed to initialize Azure OpenAI client: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            logger.error("Please check your Azure OpenAI configuration and try again.")
            raise

    def test_llm_connection(self):
        """
        Test the Azure OpenAI connection with a simple API call
        """
        try:
            logger.info("Testing Azure OpenAI connection...")
            test_messages = [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Respond with exactly: 'Connection test successful'"}
            ]

            response = self._call_llm_with_retry(test_messages, max_tokens=10)

            if "successful" in response.lower():
                logger.info("✓ Azure OpenAI connection test successful")
                return True
            else:
                logger.warning(f"⚠ Azure OpenAI responded but with unexpected content: {response}")
                return True  # Still consider it successful since we got a response

        except Exception as e:
            logger.error(f"✗ Azure OpenAI connection test failed: {e}")
            return False

    def _call_llm_with_retry(self, messages, max_tokens=8192):
        """
        Call Azure OpenAI API with retry logic using the new SDK interface
        """
        config = configuration["ai_analysis"]

        for attempt in range(config["retry_attempts"]):
            try:
                logger.info(f"Azure OpenAI API call for {len(str(messages))} characters "
                            f"in messages, max_tokens={max_tokens}")
                if len(str(messages)) > config["max_tokens"]:
                    logger.error(f"Attention: Message length {len(str(messages))} exceeds "
                                 f"max_tokens {config['max_tokens']}")

                # Log system message and prompt for debugging
                if messages:
                    logger.info("#" * 80)
                    if len(messages) > 0 and messages[0].get("role") == "system":
                        logger.info(f"SYSTEM MESSAGE:\n{messages[0].get('content', 'N/A')}")
                    logger.info("#" * 80)

                    # Log all user/assistant messages as prompt
                    prompt_messages = [msg for msg in messages if msg.get("role") in ["user", "assistant"]]
                    if prompt_messages:
                        logger.info("#" * 80)
                        logger.info("PROMPT:")
                        for msg in prompt_messages:
                            role = msg.get("role", "unknown").upper()
                            content = msg.get("content", "N/A")
                            logger.info(f"{role}: {content}")
                        logger.info("#" * 80)

                # Make the API call to Azure OpenAI using new SDK
                response = self.client.chat.completions.create(
                    model=config["deployment_name"],  # deployment name
                    messages=messages,
                    temperature=config["temperature"],
                    max_tokens=max_tokens
                )

                # Extract and return the response content
                content = response.choices[0].message.content.strip()
                logger.info(f"Azure OpenAI API call successful, response length: {len(content)} characters")
                logger.info("*" * 50)
                logger.info(f"Azure OpenAI API call successful, response content: {content}")
                logger.info("*" * 50)
                return content

            except Exception as e:
                error_msg = str(e)
                logger.warning(f"Azure OpenAI API call attempt {attempt + 1}/"
                               f"{config['retry_attempts']} failed: {error_msg}")

                # Provide specific error guidance for Azure OpenAI
                if "deployment" in error_msg.lower() and "not found" in error_msg.lower():
                    logger.error("Deployment not found. Please check:")
                    logger.error("  - Your deployment name in Azure OpenAI Studio")
                    logger.error("  - Deployment is in 'Succeeded' state")
                    logger.error("  - Update the 'deployment_name' field in configuration")
                elif "quota" in error_msg.lower() or "rate" in error_msg.lower():
                    logger.warning("Rate limit or quota exceeded. Consider:")
                    logger.warning("  - Reducing --chunk-size parameter")
                    logger.warning("  - Requesting quota increase in Azure Portal")
                elif "authentication" in error_msg.lower() or "unauthorized" in error_msg.lower():
                    logger.error("Authentication failed. Please check:")
                    logger.error("  - Your AZURE_OPENAI_API is correct")
                    logger.error("  - Your Azure OpenAI resource is active")
                elif "resource" in error_msg.lower() and "not found" in error_msg.lower():
                    logger.error("Azure OpenAI resource not found. Please check:")
                    logger.error("  - Your endpoint URL is correct")
                    logger.error("  - The resource exists and is accessible")

                if attempt < config["retry_attempts"] - 1:
                    sleep_time = config["retry_delay"] * (attempt + 1)
                    logger.info(f"Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)

        # All attempts failed
        logger.error("All retry attempts failed. Please check your Azure OpenAI configuration.")
        raise RuntimeError(f"Azure OpenAI API failed after {config['retry_attempts']} attempts")

    def preprocess_failure_data(self, df):
        """
        Preprocess failure data for LLM analysis
        1. Create DataFrame with unique summaries
        2. For each unique summary, collect all associated cases (max 20)
        3. Generate failure_info for categorization based on unique summaries
        """
        logger.info(f"Preprocessing {len(df)} failure records...")

        # Step 1: Process all rows and group by cleaned summary
        summary_to_cases = defaultdict(list)

        for idx, row in df.iterrows():
            # Clean the summary
            # cleaned_summary = self.__preprocess_summary(row.get('Summary', ''))
            # if not cleaned_summary:  # Skip empty summaries
            #     continue
            original_summary = row.get('Summary', '')

            # Create case information
            case_info = {
                'ModulePath': row.get('ModulePath', ''),
                'opTestCase': row.get('opTestCase', ''),
                'TestCase': row.get('TestCase', ''),
                'BranchName': row.get('BranchName', ''),
                'Result': row.get('Result', ''),
                'OSVersion': row.get('OSVersion', ''),
                'TestbedName': row.get('TestbedName', ''),
                'AsicType': row.get('AsicType', ''),
                'Topology': row.get('Topology', ''),
                'TopologyType': row.get('TopologyType', ''),
                'HardwareSku': row.get('HardwareSku', ''),
                'Pipeline': row.get('Pipeline', ''),
                'UploadTimestamp': str(row.get('UploadTimestamp', '')),
                'FailedType': row.get('FailedType', ''),
                'Attempt': row.get('Attempt', ''),
                'Summary': row.get('Summary', ''),
                'Feature': row.get('Feature', ''),
            }

            summary_to_cases[original_summary].append(case_info)

        logger.info(f"Found {len(summary_to_cases)} unique summaries")

        # Step 2: Create new DataFrame with unique summaries and their cases
        unique_summary_data = []

        for summary, cases in summary_to_cases.items():
            # Remove duplicate cases based on key fields to avoid same test cases
            unique_cases = []

            for case in cases:
                unique_cases.append(case)
                # Limit to top 20 unique cases
                if len(unique_cases) >= 20:
                    break

            # Get representative information from the first case
            first_case = unique_cases[0].copy() if unique_cases else {}
            first_case['summary'] = summary  # Use bracket notation instead of update
            first_case['cases_count'] = len(cases)
            first_case['all_cases'] = unique_cases
            unique_summary_data.append(first_case)

        # Create DataFrame
        unique_summary_df = pd.DataFrame(unique_summary_data)

        # Step 3: Generate failure_info for categorization based on unique summaries
        processed_failures = []

        for idx, row in unique_summary_df.iterrows():
            failure_info = row.to_dict()  # Convert to dict to ensure we have dict access
            failure_info['id'] = idx  # Use bracket notation instead of update
            processed_failures.append(failure_info)

        logger.info(f"Generated {len(processed_failures)} unique failure patterns for categorization")

        return processed_failures, unique_summary_df

    def __preprocess_summary(self, text):
        """
        Lowercases, removes numbers and punctuation, and extra whitespace.
        Adjust this function if you have specific patterns to remove.
        """
        if pd.isna(text) or not text:
            return ''

        text = text.lower()
        # text = re.sub(r'\d+', '', text)           # remove numbers
        # text = re.sub(r'[^\w\s]', '', text)         # remove punctuation
        # Pattern to match timestamps in both formats:
        # 1. At start of line: YYYY MMM DD HH:MM:SS.mmmmmm
        # 2. In middle of line: YYYY-MM-DD HH:MM:SS.mmmmmm
        # 3. Delta format: 0:00:00.039462
        timestamp_patterns = [
            r'^\d{4}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+',  # Start of line format
            r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+',  # Middle of line format
            r'\d+:\d{2}:\d{2}\.\d+'  # Delta format
        ]

        # Process each line
        cleaned_lines = []
        for line in text.split('\n'):
            if line.strip():  # Skip empty lines
                # Remove timestamps
                for pattern in timestamp_patterns:
                    line = re.sub(pattern, '', line)

                # Pattern to match hostname with various delimiters
                # Matches: (start of line or space or hyphen or [ or " or ' or :) + hostname +
                # (space or quote or angle bracket or square bracket or - or , or })
                hostname_pattern = (r'(?:^|\s+|-|\[|"|\'|:)(' + self.HOST_RE.pattern[1:-1] +
                                    r')(?=[\s\'">\]]|-|,|}|$)')

                # Remove hostnames
                line = re.sub(hostname_pattern, '', line)
                cleaned_lines.append(line)
        cleaned_lines = '\n'.join(cleaned_lines)
        if "traceback" in cleaned_lines or "analyze_logs" in cleaned_lines:
            # logger.info("Remove numbers from summary since it's a traceback or analyze log")
            cleaned_lines = re.sub(r'\d+', '', cleaned_lines)           # remove numbers
        return cleaned_lines

    def _clean_summary(self, summary):
        """
        Clean failure summary for better LLM analysis
        """
        if pd.isna(summary) or not isinstance(summary, str):
            return ""

        # Remove excessive details while keeping important error patterns
        # summary = re.sub(r'grpc_status:\d+', 'grpc_status:[STATUS]', summary)
        # summary = re.sub(r'created_time:"[^"]*"', 'created_time:"[TIMESTAMP]"', summary)
        summary = re.sub(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}[.\d]*[+\d:Z]*', '[TIMESTAMP]', summary)
        # summary = re.sub(r'\d+\.\d+\.\d+\.\d+', '[IP_ADDRESS]', summary)
        # summary = re.sub(r'port\s+\d+', 'port [PORT]', summary)
        # summary = re.sub(r'timeout\s*\(\s*\d+s?\s*\)', 'timeout ([TIME])', summary, flags=re.IGNORECASE)
        summary = re.sub(r'\s+', ' ', summary)

        # Truncate very long summaries
        # if len(summary) > 500:
        #     summary = summary[:500] + "..."

        return summary.strip()

    def categorize_failures_with_llm(self, failures):
        """
        Use LLM to categorize failures into groups using shared batch processing
        """
        logger.info(f"Categorizing {len(failures)} failures using LLM...")

        # If we have small number of failures that fit in one batch, no need for consolidation
        if len(failures) <= self.chunk_size:
            logger.info(f"Small dataset ({len(failures)} <= {self.chunk_size}), "
                        f"using single batch without consolidation")
            categories = self._categorize_chunk(failures)

            # Log category summary for debugging
            for cat_name, failure_ids in categories.items():
                logger.info(f"Category '{cat_name}': {len(failure_ids)} failures - {failure_ids}")

            return categories

        # For larger datasets, use batch processing and consolidate
        logger.info(f"Large dataset ({len(failures)} > {self.chunk_size}), using batch processing with consolidation")

        # Process failures in batches using shared batch function
        batch_results = self._process_llm_in_batches(
            items=failures,
            batch_size=self.chunk_size,
            process_function=self._categorize_chunk
        )

        # Merge all batch results into a single category dictionary
        all_categories = {}
        for batch_categories in batch_results:
            if batch_categories:  # Skip None results
                for category_name, failure_ids in batch_categories.items():
                    if category_name not in all_categories:
                        all_categories[category_name] = []
                    all_categories[category_name].extend(failure_ids)

        logger.info(f"Created {len(all_categories)} failure categories before consolidation")
        logger.debug(f"All categories before consolidation: {json.dumps(all_categories, indent=2)}")
        # Consolidate similar categories across chunks
        consolidated_categories = self._consolidate_similar_categories(all_categories, failures)

        logger.info(f"After consolidation: {len(consolidated_categories)} failure categories")
        logger.debug(f"Consolidated categories: {json.dumps(consolidated_categories, indent=2)}")

        # Log category summary for debugging
        for cat_name, failure_ids in consolidated_categories.items():
            logger.info(f"Category '{cat_name}': {len(failure_ids)} failures - {failure_ids}")

        return consolidated_categories

    def _categorize_chunk(self, failures_chunk):
        """
        Categorize a chunk of failures using LLM
        """
        # Create prompt for categorization
        prompt = self._create_categorization_prompt(failures_chunk)

        system_message = """You are an expert software test failure analyzer specializing in network
and system testing (SONiC).
Your task is to categorize test failures into logical groups based on their root causes and failure patterns.

Guidelines:
1. Group failures that share the same underlying cause or error pattern
2. Create meaningful category names that describe the root cause, use "_" to separate words
   for category name, category name should not exceed 4 words (e.g., "bgp_sanity_check_failure")
3. Consider both the failure type and the specific error details in summary
4. Each failure should belong to exactly one category

Return your analysis as a JSON object with this structure:
{
  "categories": {
    "category_name_a": {
      "description": "Brief description of the failure pattern",
      "failure_ids": [list of failure IDs that belong to this category]
    },
    "category_name_b": {
      "description": "Brief description of the failure pattern",
      "failure_ids": [list of failure IDs that belong to this category]
    }
  }
}"""

        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt}
        ]
        logger.info("Processing categorization...")

        # Call LLM with retry logic
        logger.info(f"Azure OpenAI API call for {len(system_message)} system messages and "
                    f"length {len(prompt)} prompt characters, total length: {len(str(messages))} characters")
        try:
            response = self._call_llm_with_retry(messages)
            return self._parse_categorization_response(response, failures_chunk)
        except Exception as e:
            logger.error(f"Failed to categorize chunk: {e}")
            # Fallback: create simple categories based on failure type
            return self._create_fallback_categories(failures_chunk)

    def _create_categorization_prompt(self, failures):
        """
        Create a prompt for LLM to categorize failures
        """
        prompt = ("Please categorize the following test failures based on their root causes "
                  "and error patterns:\n\n")

        for i, failure in enumerate(failures):
            prompt += f"Failure ID: {failure['id']}\n"
            prompt += f"Module: {failure['ModulePath']}\n"
            prompt += f"Test: {failure['opTestCase']}\n"
            prompt += f"Failed Type: {failure['FailedType']}\n"
            prompt += f"Summary: {failure['Summary']}\n"
            prompt += "-" * 50 + "\n"

        prompt += ("\nAnalyze these failures and group them into logical categories based on common "
                   "root causes or error patterns. Return the result as JSON with category names, "
                   "descriptions, and lists of failure IDs.")

        return prompt

    def _clean_json_response(self, response):
        """
        Clean the JSON response by removing common formatting issues
        """
        if not response:
            return response

        # Remove markdown code blocks if present
        response = re.sub(r'^```(?:json)?\s*\n?', '', response, flags=re.MULTILINE)
        response = re.sub(r'\n?```\s*$', '', response, flags=re.MULTILINE)

        # Remove leading/trailing whitespace
        response = response.strip()

        # Try to fix common JSON issues
        # Remove trailing commas before closing braces/brackets
        response = re.sub(r',(\s*[}\]])', r'\1', response)

        # Remove extra closing braces at the end (common OpenAI issue)
        # Count opening and closing braces to find extras
        open_braces = response.count('{')
        close_braces = response.count('}')
        if close_braces > open_braces:
            # Remove extra closing braces from the end
            extra_braces = close_braces - open_braces
            for _ in range(extra_braces):
                # Remove the last occurrence of }
                last_brace_idx = response.rfind('}')
                if last_brace_idx != -1:
                    response = response[:last_brace_idx] + response[last_brace_idx+1:]

        return response

    def _fix_invalid_json_response(self, invalid_json, response_type="JSON response"):
        """
        Ask OpenAI to fix invalid JSON response
        """
        try:
            logger.info(f"Attempting to fix invalid {response_type}")

            fix_prompt = f"""The following {response_type} contains invalid JSON syntax.
Please fix it and return only the corrected JSON:

{invalid_json}

Please return only valid JSON without any additional text, explanations, or markdown formatting."""

            messages = [
                {"role": "system",
                 "content": "You are a JSON repair assistant. Your job is to fix "
                    "invalid JSON and return only the corrected JSON without "
                    "any additional text."},
                {"role": "user", "content": fix_prompt}
            ]

            # Use a shorter max_tokens for JSON correction
            corrected_response = self._call_llm_with_retry(messages, max_tokens=4096)

            if corrected_response:
                # Clean the corrected response
                cleaned_corrected = self._clean_json_response(corrected_response)

                # Test if it's valid JSON
                try:
                    json.loads(cleaned_corrected)
                    logger.info(f"Successfully fixed invalid {response_type}")
                    return cleaned_corrected
                except json.JSONDecodeError as e:
                    logger.debug(f"cleaned_corrected: {cleaned_corrected}")
                    logger.error(f"Fixed {response_type} is still invalid JSON: {e}")
                    return None
            else:
                logger.error(f"Failed to get corrected {response_type} from OpenAI")
                return None

        except Exception as e:
            logger.error(f"Error while fixing invalid {response_type}: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def _parse_categorization_response(self, response, failures_chunk):
        """
        Parse LLM response for categorization
        """
        try:
            # First attempt: try to parse the response directly
            cleaned_response = self._clean_json_response(response)

            try:
                data = json.loads(cleaned_response)
            except json.JSONDecodeError as e:
                logger.debug(f"cleaned_response: {cleaned_response}")
                logger.warning(f"Initial JSON parsing failed for categorization: {e}")
                logger.warning("Attempting to fix invalid JSON response...")

                # Second attempt: ask OpenAI to fix the JSON
                fixed_json = self._fix_invalid_json_response(response, "failure categorization response")
                if fixed_json:
                    data = json.loads(fixed_json)
                    logger.info("Successfully parsed corrected categorization JSON response")
                else:
                    logger.error("Failed to fix invalid categorization JSON response")
                    return self._create_fallback_categories(failures_chunk)

            # Process the parsed JSON data
            categories = {}
            if 'categories' in data:
                for cat_name, cat_info in data['categories'].items():
                    if 'failure_ids' in cat_info:
                        # Ensure failure IDs are valid integers that exist in our failures list
                        valid_failure_ids = []
                        for fid in cat_info['failure_ids']:
                            try:
                                fid_int = int(fid)
                                valid_failure_ids.append(fid_int)
                            except (ValueError, TypeError):
                                logger.warning(f"Invalid failure ID '{fid}' in category '{cat_name}', skipping")

                        if valid_failure_ids:
                            categories[cat_name] = valid_failure_ids
                        else:
                            logger.warning(f"No valid failure IDs found for category '{cat_name}'")

            logger.info(f"Parsed categories: {json.dumps(categories, indent=2)}")
            return categories

        except Exception as e:
            logger.error(f"Failed to parse LLM categorization response: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return self._create_fallback_categories(failures_chunk)

    def _create_fallback_categories(self, failures):
        """
        Create fallback categories based on failure type
        """
        categories = defaultdict(list)

        for failure in failures:
            failed_type = failure.get('FailedType', '') or 'Unknown'
            category_name = f"{failed_type}_Failures"
            categories[category_name].append(failure['id'])

        return dict(categories)

    def _consolidate_similar_categories(self, categories, failures):
        """
        Consolidate similar categories that may have been created in different chunks
        """
        logger.info("Consolidating similar categories across chunks...")

        failure_lookup = {f['id']: f for f in failures}

        # Create category representatives with sample summaries for comparison
        category_info = {}
        for cat_name, failure_ids in categories.items():
            if failure_ids:
                # Get sample failures from this category
                sample_failures = [failure_lookup[fid] for fid in failure_ids[:1] if fid in failure_lookup]
                sample_summaries = [f.get('Summary', '') for f in sample_failures if f.get('Summary')]

                category_info[cat_name] = {
                    'failure_ids': failure_ids,
                    'sample_summaries': sample_summaries,
                    'failed_types': list(set([failure_lookup[fid].get('FailedType', '')
                                             for fid in failure_ids if fid in failure_lookup])),
                    'size': len(failure_ids)
                }
        logger.info(f"Created category info for consolidation: "
                    f"{json.dumps(convert_timestamps_to_strings(category_info), indent=2)}")

        # Group categories by failed_types before consolidation
        grouped_category_info = self._group_categories_by_failed_types(category_info)
        logger.info(f"Created grouped category info for consolidation: "
                    f"{json.dumps(convert_timestamps_to_strings(grouped_category_info), indent=2)}")

        # Use LLM to identify similar categories for consolidation within each group
        consolidated = self._llm_consolidate_categories(grouped_category_info, failures)

        # If LLM consolidation fails, use rule-based fallback
        if not consolidated:
            logger.warning("LLM consolidation failed, using rule-based consolidation")
            consolidated = self._rule_based_consolidate_categories(category_info)

        return consolidated

    def _llm_consolidate_categories(self, grouped_categories, failures):
        """
        Use LLM to identify and merge similar categories within each failed_type group,
        processing in batches if needed. Only one round of consolidation is performed.

        Args:
            grouped_categories: Dict with failed_type as keys and category dicts as values
                               e.g., {"Infrastructure": {cat1: info1, ...}, "mixed_failed_type": {...}}
            failures: List of all failures for summary lookup

        Returns:
            Dict mapping consolidated category names to failure_ids
        """
        logger.info("Starting LLM consolidation of categories by failed_type groups")

        if not grouped_categories:
            return {}

        final_consolidated = {}

        # Process each failed_type group separately
        for group_key, category_info in grouped_categories.items():
            logger.info(f"Processing consolidation for group '{group_key}' with {len(category_info)} categories")

            if len(category_info) <= 1:
                # No consolidation needed for single category
                for name, info in category_info.items():
                    final_consolidated[name] = info['failure_ids']
                continue

            # Consolidate within this group using batching if needed
            max_categories_per_batch = configuration["ai_analysis"]["consolidation_batch_size"]

            if len(category_info) <= max_categories_per_batch:
                group_result = self._process_single_consolidation_batch(category_info)
            else:
                group_result = self._process_consolidation_in_batches(category_info, max_categories_per_batch)
            data_view = {}
            if group_result:
                logger.info(f"group results for '{group_key}': {json.dumps(group_result, indent=2)}")
                # Add results from this group to final result
                for cat_name, failure_ids in group_result.items():
                    final_consolidated[cat_name] = failure_ids

                    # Find original category info for this consolidated category
                    original_info = category_info.get(cat_name, {})

                    # Get failure lookup for summaries
                    failure_lookup = {f['id']: f for f in failures}

                    # Get sample summaries from the failure IDs
                    sample_summaries = []
                    for fid in failure_ids:
                        if fid in failure_lookup:
                            summary = failure_lookup[fid].get('Summary', '')
                            if summary:
                                sample_summaries.append(summary[:500])  # Truncate for readability

                    data_view[cat_name] = {
                        'failure_count': len(failure_ids),
                        'failure_ids': failure_ids,
                        'sample_summaries': sample_summaries,
                        'failed_types': original_info.get('failed_types', []),
                        'original_size': original_info.get('size', len(failure_ids)),
                        'group': group_key
                    }
            else:
                # If consolidation failed, keep original categories
                logger.warning(f"Consolidation failed for group '{group_key}', keeping original categories")
                for cat_name, info in category_info.items():
                    final_consolidated[cat_name] = info['failure_ids']
            logger.info(f"group '{group_key}' consolidation complete. Category status:")
            count = 0
            for cat_name, cat_info in data_view.items():
                logger.info(f"  {count + 1}: {cat_name}: {cat_info['failure_count']} failures "
                            f"(original: {cat_info['original_size']})")
                logger.info(f"    Failed Types: {cat_info['failed_types']}")
                for idx, summary in enumerate(cat_info['sample_summaries']):
                    logger.info(f"    Summary {idx + 1}: {summary}")
                count += 1
            logger.info(f"group '{group_key}' total categories after consolidation: {len(data_view)}")

        logger.info(f"Completed consolidation. Final result has {len(final_consolidated)} categories")
        logger.debug(f"Final consolidated categories: {json.dumps(final_consolidated, indent=2)}")
        return final_consolidated

    def _process_consolidation_in_batches(self, category_info, batch_size):
        """
        Process category consolidation in smaller batches to avoid token limits
        """
        logger.info(f"Processing {len(category_info)} categories in batches of {batch_size} to avoid token limits")

        category_items = list(category_info.items())
        consolidated_categories = {}

        # Process categories in batches
        for i in range(0, len(category_items), batch_size):
            batch_items = category_items[i:i + batch_size]
            batch_info = dict(batch_items)

            logger.info(f"Processing consolidation batch {i//batch_size + 1}: {len(batch_info)} categories")

            # Process this batch
            batch_result = self._process_single_consolidation_batch(batch_info)

            if batch_result:
                # Merge results from this batch
                for cat_name, failure_ids in batch_result.items():
                    consolidated_categories[cat_name] = failure_ids
            else:
                # If batch processing failed, keep original categories
                for cat_name, info in batch_info.items():
                    consolidated_categories[cat_name] = info['failure_ids']

        # After processing all batches, return the results
        # Only one round of consolidation is performed as requested
        logger.info(f"Completed batch processing with {len(consolidated_categories)} "
                    f"consolidated categories")
        return consolidated_categories

    def _process_single_consolidation_batch(self, category_info):
        """
        Process a single batch of categories for consolidation
        """
        try:
            # Create prompt for category consolidation
            prompt = ("Review the following Sample Summaries and identify which ones should be merged "
                      "because they represent the same type of failure:\n\n")

            for i, (cat_name, info) in enumerate(category_info.items()):
                prompt += f"Category {i+1}: {cat_name}\n"
                prompt += f"  Size: {info['size']} failures\n"
                if info.get('failed_types'):
                    prompt += f"  Failed Types: {', '.join(info['failed_types'])}\n"
                if info.get('sample_summaries'):
                    prompt += "  Sample Summary:\n"
                    for j, summary in enumerate(info['sample_summaries'][:1]):
                        # Truncate very long summaries to save tokens
                        # truncated_summary = summary[:200] if len(summary) > 200 else summary
                        prompt += f"    - {summary}\n"
                prompt += "\n"

            prompt += """
Identify which categories should be merged and return the result as JSON.
"""

            # Check prompt length and truncate if necessary
            if len(prompt) > 8000:  # Conservative limit
                logger.warning(f"Consolidation prompt too long ({len(prompt)} chars), truncating summaries")
                # Rebuild prompt with shorter summaries
                prompt = ("Review the following Sample categories and identify which ones should be "
                          "merged:\n\n")
                for i, (cat_name, info) in enumerate(category_info.items()):
                    prompt += f"Category {i+1}: {cat_name} (Size: {info['size']})\n"
                    if info.get('sample_summaries'):
                        # Use only first summary and truncate heavily
                        summary = info['sample_summaries'][0] if info['sample_summaries'] else ""
                        truncated_summary = summary[:200] if len(summary) > 200 else summary
                        prompt += f"  Sample: {truncated_summary}...\n"
                    prompt += "\n"
                prompt += """
Return JSON with consolidation_groups (array of category names to merge) and unchanged_categories arrays.
"""

            system_message = """You are an expert at analyzing software test failure patterns to identify duplicate \
or overlapping categories that should be consolidated.

Guidelines:
- Analyze these categories and their summaries and identify groups that should be merged because
  they represent the same underlying failure pattern
- Only merge categories if the similarity of Sample Summary is more than 90%
- Only merge categories that their summaries clearly represent the same failure type
- Include categories that don't need merging in unchanged_categories
- Make sure the returned JSON is valid and well-formed

Return a JSON object with this structure:
{
  "merged_categories": ["category_name_a", "category_name_b", "category_name_c"],
  "unchanged_categories": ["category_name_d", "category_name_e"]
}

Where merged_categories contains category names that should be merged together"""

            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]
            # logger.debug(f"Consolidation prompt : {prompt}")
            logger.info(f"Consolidation batch: {len(category_info)} categories, prompt length: {len(prompt)} chars")
            response = self._call_llm_with_retry(messages)

            return self._parse_consolidation_response(response, category_info)

        except Exception as e:
            logger.error(f"Batch consolidation failed: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def _parse_consolidation_response(self, response, category_info):
        """
        Parse LLM response for category consolidation
        """
        try:
            # First attempt: try to parse the response directly
            cleaned_response = self._clean_json_response(response)

            try:
                data = json.loads(cleaned_response)
            except json.JSONDecodeError as e:
                logger.debug(f"cleaned_response: {cleaned_response}")
                logger.warning(f"Initial JSON parsing failed: {e}")
                logger.warning("Attempting to fix invalid JSON response...")

                # Second attempt: ask OpenAI to fix the JSON
                fixed_json = self._fix_invalid_json_response(response, "category consolidation response")
                if fixed_json:
                    data = json.loads(fixed_json)
                    logger.info("Successfully parsed corrected JSON response")
                else:
                    logger.error("Failed to fix invalid JSON response")
                    return None

            consolidated_categories = {}            # Process consolidation groups (new simple array format)
            if 'merged_categories' in data:
                merged_categories = data['merged_categories']

                # Handle different formats
                if merged_categories and isinstance(merged_categories, list):
                    if len(merged_categories) >= 1:  # New simple format: direct array of category names to merge
                        logger.info(f"Found merged categories: {merged_categories}")
                        if isinstance(merged_categories[0], str):
                            # New simple format: ["cat_a", "cat_b", "cat_c"] - merge all into first one
                            merged_name = merged_categories[0]  # First category becomes merged name
                            original_cats = merged_categories

                            # Merge failure IDs from original categories
                            merged_failure_ids = []
                            valid_original_cats = []

                            for orig_cat in original_cats:
                                if orig_cat in category_info:
                                    merged_failure_ids.extend(category_info[orig_cat]['failure_ids'])
                                    valid_original_cats.append(orig_cat)

                            if merged_failure_ids:
                                consolidated_categories[merged_name] = merged_failure_ids
                                logger.info(f"Merged categories {valid_original_cats} -> '{merged_name}'")
                                logger.info(f"Merged failure IDs: {merged_failure_ids}")

                        elif isinstance(merged_categories[0], list):
                            logger.info(f"Found merged categories type list: {merged_categories}")
                            # Old format: array of arrays [["cat_a", "cat_b"], ["cat_c", "cat_d"]]
                            for group_array in merged_categories:
                                if len(group_array) >= 2:  # Need at least 2 categories to merge
                                    merged_name = group_array[0]  # First category becomes merged name
                                    original_cats = group_array

                                    # Merge failure IDs from original categories
                                    merged_failure_ids = []
                                    valid_original_cats = []

                                    for orig_cat in original_cats:
                                        if orig_cat in category_info:
                                            merged_failure_ids.extend(category_info[orig_cat]['failure_ids'])
                                            valid_original_cats.append(orig_cat)

                                    if merged_failure_ids:
                                        consolidated_categories[merged_name] = merged_failure_ids
                                        logger.info(f"Merged categories {valid_original_cats} -> "
                                                    f"'{merged_name}' (array format)")

                        elif isinstance(merged_categories[0], dict):
                            # Oldest format: array of objects (fallback compatibility)
                            for group in merged_categories:
                                merged_name = group.get('merged_name', '')
                                original_cats = group.get('original_categories', [])

                                if merged_name and original_cats:
                                    # Merge failure IDs from original categories
                                    merged_failure_ids = []
                                    valid_original_cats = []

                                    for orig_cat in original_cats:
                                        if orig_cat in category_info:
                                            merged_failure_ids.extend(category_info[orig_cat]['failure_ids'])
                                            valid_original_cats.append(orig_cat)

                                    if merged_failure_ids:
                                        consolidated_categories[merged_name] = merged_failure_ids
                                        logger.info(f"Merged categories {valid_original_cats} -> "
                                                    f"'{merged_name}' (old object format)")

            # Add unchanged categories
            unchanged_cats = data.get('unchanged_categories', [])
            for cat_name in unchanged_cats:
                if cat_name in category_info:
                    # Add any categories not mentioned in the response
                    consolidated_categories[cat_name] = category_info[cat_name]['failure_ids']
            mentioned_cats = set()
            if 'merged_categories' in data:
                merged_categories = data['merged_categories']

                if merged_categories and isinstance(merged_categories, list):
                    if isinstance(merged_categories[0], str):
                        # New simple format: direct array of category names
                        mentioned_cats.update(merged_categories)
                    elif isinstance(merged_categories[0], list):
                        # Array of arrays format
                        for group_array in merged_categories:
                            mentioned_cats.update(group_array)
                    elif isinstance(merged_categories[0], dict):
                        # Old format: array of objects (fallback compatibility)
                        for group in merged_categories:
                            mentioned_cats.update(group.get('original_categories', []))
            mentioned_cats.update(unchanged_cats)

            for cat_name, info in category_info.items():
                if cat_name not in mentioned_cats:
                    consolidated_categories[cat_name] = info['failure_ids']
                    logger.info(f"Category '{cat_name}' not mentioned in response, keeping unchanged")

            return consolidated_categories

        except Exception as e:
            logger.error(f"Failed to parse consolidation response: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def _rule_based_consolidate_categories(self, category_info):
        """
        Rule-based consolidation as fallback when LLM fails
        """
        logger.info("Using rule-based category consolidation")

        consolidated = {}
        processed_categories = set()

        category_names = list(category_info.keys())

        for i, cat1 in enumerate(category_names):
            if cat1 in processed_categories:
                continue

            # Start a new merged category
            merged_failure_ids = category_info[cat1]['failure_ids'].copy()
            merged_name = cat1
            merged_categories = [cat1]

            # Look for similar categories to merge
            for j, cat2 in enumerate(category_names[i+1:], i+1):
                if cat2 in processed_categories:
                    continue

                # Check if categories should be merged based on rules
                should_merge = self._should_merge_categories(
                    category_info[cat1], category_info[cat2]
                )
                if should_merge:
                    merged_failure_ids.extend(category_info[cat2]['failure_ids'])
                    merged_categories.append(cat2)
                    processed_categories.add(cat2)

                    # Update merged name to be more generic
                    merged_name = self._create_merged_category_name(cat1, cat2)

            consolidated[merged_name] = merged_failure_ids
            processed_categories.add(cat1)

            if len(merged_categories) > 1:
                logger.info(f"Rule-based merge: {merged_categories} -> '{merged_name}'")

        return consolidated

    def _should_merge_categories(self, cat1_info, cat2_info):
        """
        Determine if two categories should be merged based on rules
        """
        # Check if failed types overlap significantly
        failed_types1 = set(cat1_info['failed_types'])
        failed_types2 = set(cat2_info['failed_types'])

        if failed_types1 & failed_types2:  # Has common failed types
            # Check for similar summary patterns
            summaries1 = cat1_info['sample_summaries']
            summaries2 = cat2_info['sample_summaries']

            # Look for common error patterns
            for s1 in summaries1[:2]:
                for s2 in summaries2[:2]:
                    similarity = self._calculate_summary_similarity(s1, s2)
                    if similarity > 0.7:  # High similarity threshold
                        return True

        return False

    def _calculate_summary_similarity(self, summary1, summary2):
        """
        Calculate similarity between two failure summaries
        """
        if not summary1 or not summary2:
            return 0.0

        # Normalize summaries
        s1 = re.sub(r'[^\w\s]', ' ', summary1.lower())
        s2 = re.sub(r'[^\w\s]', ' ', summary2.lower())

        words1 = set(s1.split())
        words2 = set(s2.split())

        if not words1 or not words2:
            return 0.0

        # Calculate Jaccard similarity
        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0.0

    def _create_merged_category_name(self, cat1, cat2):
        """
        Create a name for merged categories
        """
        # Extract common patterns
        words1 = set(re.findall(r'\w+', cat1.lower()))
        words2 = set(re.findall(r'\w+', cat2.lower()))

        common_words = words1 & words2

        if common_words:
            # Use common words for the merged name
            merged_name = '_'.join(sorted(common_words)).title() + '_Failures'
        else:
            # Fallback: use the shorter category name
            merged_name = cat1 if len(cat1) <= len(cat2) else cat2

        return merged_name

    def select_representatives(self, failures, categories):
        """
        Select representative cases for each category, avoiding duplicate case+branch combinations
        """
        representatives = []
        failure_lookup = {f['id']: f for f in failures}
        used_cases = set()  # Track case+branch combinations already used as representatives

        for category_name, failure_ids in categories.items():
            logger.info(f"Processing category '{category_name}' with {len(failure_ids)} failures")

            if len(failure_ids) < 1:
                continue

            category_failures = [failure_lookup[fid] for fid in failure_ids if fid in failure_lookup]
            logger.info(f"Found {len(category_failures)} valid failures for category {category_name}")

            if not category_failures:
                logger.warning(f"No valid failures found for category {category_name}")
                continue

            # Find a suitable representative that hasn't been used yet
            selected_failure = None
            for failure in category_failures:
                # Create unique identifier for this case+branch combination
                test_case = failure.get('opTestCase', failure.get('TestCase', ''))
                case_id = (f"{failure.get('ModulePath', '')}.{test_case}"
                           f"#{failure.get('BranchName', '')}")

                if case_id not in used_cases:
                    selected_failure = failure
                    used_cases.add(case_id)
                    logger.info(f"✓ Selected as representative for {category_name}: {case_id}")
                    break
                else:
                    logger.debug(f"Skipping already used case+branch: {case_id}")

            # If all cases in this category are already used, fall back to the first one
            if selected_failure is None:
                selected_failure = category_failures[0]
                case_id = (f"{selected_failure.get('ModulePath', '')}."
                           f"{selected_failure.get('opTestCase', selected_failure.get('TestCase', ''))}"
                           f"#{selected_failure.get('BranchName', '')}")
                logger.warning(f"All cases in category '{category_name}' are already used as "
                               f"representatives. Using fallback: {case_id}")

            # Aggregate all correlate_cases from all failures in this category
            all_correlate_cases = []

            for failure in category_failures:
                failure_cases = failure.get('all_cases', [])
                if isinstance(failure_cases, list):
                    for case in failure_cases:
                        # Create a unique identifier for deduplication
                        # case_key = None
                        # if isinstance(case, dict):
                        #     case_key = (f"{case.get('ModulePath', '')}."
                        #                 f"{case.get('opTestCase', case.get('TestCase', ''))}"
                        #                 f".{case.get('BranchName', '')}")
                        # elif isinstance(case, str):
                        #     case_key = case
                        # else:
                        #     case_key = str(case)

                        # if case_key and case_key not in seen_cases:
                        #     seen_cases.add(case_key)
                        all_correlate_cases.append(case)

                        # Limit to max 20 cases
                        if len(all_correlate_cases) >= 20:
                            break

                if len(all_correlate_cases) >= 20:
                    break

            logger.info(f"Aggregated {len(all_correlate_cases)} unique correlate cases for "
                        f"category {category_name}")

            representative = self._format_representative(selected_failure, category_name,
                                                         len(category_failures), all_correlate_cases)

            if representative:
                representatives.append(representative)
                logger.info(f"✓ Added representative for {category_name} with "
                            f"{len(all_correlate_cases)} correlate cases")
            else:
                logger.error(f"✗ Failed to format representative for {category_name}")

        return representatives

    # Not used currently, but keep for future use
    def _select_representative_for_category(self, category_name, category_failures, used_cases):
        """
        Select the best representative case for a category using LLM
        """
        # Filter out already used cases (same exact test case + branch combination)
        available_failures = []
        for failure in category_failures:
            # Create a more specific case_id that includes the category to allow same test in different categories
            case_id = (f"{failure.get('ModulePath', '')}_{failure.get('opTestCase', failure.get('TestCase', ''))}"
                       f"_{failure.get('BranchName', '')}")

            # Only exclude if the exact same case was used for the exact same category
            # This allows the same test to represent different categories if needed
            if case_id not in used_cases:
                available_failures.append(failure)
            else:
                logger.info(f"Skipping already used case: {case_id}")

        if not available_failures:
            logger.warning(f"No available representatives for category {category_name}")
            logger.info(f"Category {category_name} has {len(category_failures)} total failures, "
                        f"but all are already used")

            # As a fallback, allow reusing a case if absolutely necessary
            if category_failures:
                logger.info(f"Using fallback representative for {category_name}")
                failure = category_failures[0]  # Use the first available failure
                return self._format_representative(failure, category_name,
                                                   len(category_failures))
            return None

        if len(available_failures) == 1:
            failure = available_failures[0]
            return self._format_representative(failure, category_name, len(category_failures))

        # Use LLM to select the best representative
        prompt = f"""Given the following test failures in the category "{category_name}", select the BEST \
representative case.

Consider these criteria:
1. Most typical/common failure pattern in the category
2. Clear and informative failure summary
3. Recent occurrence
4. Reliable reproduction scenario

Failures in this category:
"""

        for i, failure in enumerate(available_failures[:10]):  # Limit to top 10 to avoid token limits
            prompt += f"\nOption {i+1}:\n"
            prompt += f"  Full Case: {failure.get('FullCaseName', '')}\n"
            prompt += f"  Module: {failure.get('ModulePath', '')}\n"
            prompt += f"  Test: {failure.get('opTestCase', failure.get('TestCase', ''))}\n"
            prompt += f"  Failed Type: {failure.get('FailedType', '')}\n"
            prompt += f"  Branch: {failure.get('BranchName', '')}\n"
            prompt += f"  Summary: {failure.get('Summary', '')[:200]}...\n"
            prompt += f"  Hardware: {failure.get('HardwareSku', '')}\n"
            prompt += f"  Timestamp: {failure.get('UploadTimestamp', '')}\n"

        prompt += (f"\nSelect the option number (1-{len(available_failures)}) that best represents "
                   f"this failure category. ")
        prompt += "Respond with just the number and a brief explanation."

        try:
            response = self._call_llm_with_retry([
                {"role": "system", "content": "You are selecting the best representative test case "
                                              "for a failure category."},
                {"role": "user", "content": prompt}
            ])

            # Check if response is empty
            if not response.strip():
                logger.warning(f"LLM response for {category_name} was empty, using first available")
                return self._format_representative(available_failures[0], category_name,
                                                   len(category_failures))
            # Extract option number from response
            option_match = re.search(r'\b(\d+)\b', response)
            if option_match:
                option_num = int(option_match.group(1))
                if 1 <= option_num <= len(available_failures):
                    selected_failure = available_failures[option_num - 1]
                    return self._format_representative(selected_failure, category_name,
                                                       len(category_failures))

            # Fallback to first option
            logger.warning(f"Could not parse LLM selection for {category_name}, using first available")
            return self._format_representative(available_failures[0], category_name,
                                               len(category_failures))

        except Exception as e:
            logger.error(f"Failed to select representative with LLM for {category_name}: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return self._format_representative(available_failures[0], category_name,
                                               len(category_failures))

    def _format_representative(self, failure, category_name, category_size, aggregated_correlate_cases=None):
        """
        Format a failure as a representative case
        """
        # Use aggregated correlate cases if provided, otherwise fallback to failure's cases
        correlate_cases = (aggregated_correlate_cases if aggregated_correlate_cases is not None
                           else failure.get('all_cases', []))

        return {
            'upload_timestamp': failure.get('UploadTimestamp', ''),
            'full_casename': failure.get('FullCaseName', ''),
            'subject': f"[{failure.get('ModulePath', '')}][{failure.get('opTestCase', '')}]"
                       f"[{failure.get('BranchName', '')}]",
            'branch': failure.get('BranchName', ''),
            'AI_flaky_category': category_name,
            'category_size': category_size,
            'failed_type': failure.get('FailedType', ''),
            'failure_summary': failure.get('Summary', ''),
            'topology': failure.get('Topology', ''),
            'hardware_sku': failure.get('HardwareSku', ''),
            'pipeline': failure.get('Pipeline', ''),
            'module_path': failure.get('ModulePath', ''),
            'test_case': failure.get('opTestCase', ''),
            'correlate_cases': correlate_cases,
        }

    def analyze_flaky_cases(self, flaky_case_original_df):
        """
        Main analysis function using Azure OpenAI
        """
        # Validate input DataFrame
        if flaky_case_original_df is None or flaky_case_original_df.empty:
            logger.error("Invalid input DataFrame")
            return None

        # Filter for actual failures (exclude success cases)
        failure_filter = flaky_case_original_df['Result'].isin(['failure', 'error'])
        failure_df = flaky_case_original_df[failure_filter].copy()
        logger.info(f"Found {len(failure_df)} failure cases to analyze")

        if len(failure_df) < 2:
            logger.warning("Not enough failure cases to perform analysis")
            return pd.DataFrame()

        # Preprocess failures with unique summary generation
        failures, unique_summary_df = self.preprocess_failure_data(failure_df)
        # Save to CSV file if path provided
        # For CSV output, convert the cases list to JSON string for storage
        csv_df = unique_summary_df.copy()
        csv_df['all_cases_json'] = csv_df['all_cases'].apply(
            lambda x: json.dumps(convert_timestamps_to_strings(x), indent=2))
        csv_df = csv_df.drop('all_cases', axis=1)  # Remove original list column

        csv_df.to_csv(AI_FLAKY_UNIQUE_SUMMARY_CSV, index=True)
        logger.info(f"Saved unique summaries DataFrame to: {AI_FLAKY_UNIQUE_SUMMARY_CSV}")
        # Save failures data for debugging
        failures_df = pd.DataFrame(failures)

        failures_df.to_csv(AI_FLAKY_FAILURES_DATA_CSV, index=True)
        logger.info(f"Saved failures data to: {AI_FLAKY_FAILURES_DATA_CSV}")

        # Categorize failures using LLM
        categories = self.categorize_failures_with_llm(failures)

        # Select representatives using LLM
        representatives = self.select_representatives(failures, categories)

        if not representatives:
            logger.warning("No representative cases found")
            return pd.DataFrame()

        # Create output DataFrame
        output_df = pd.DataFrame(representatives)

        # Sort by category size (most frequent failures first)
        output_df = output_df.sort_values(['category_size'], ascending=[False])

        logger.info(f"Azure OpenAI analysis complete. Found {len(output_df)} representative failure types")

        return output_df

    def _group_categories_by_failed_types(self, category_info):
        """
        Group categories by their failed_types before consolidation.
        Returns a dictionary with failed_type as keys and category dictionaries as values.
        Categories with multiple failed_types are grouped under "mixed_failed_type".
        """
        logger.info("Grouping categories by failed_types for better consolidation")

        # Group categories by their failed_types pattern
        grouped_by_type = {}  # failed_type/mixed_failed_type -> {category_name: category_info}

        for cat_name, cat_info in category_info.items():
            failed_types = cat_info.get('failed_types', [])

            if len(failed_types) == 1:
                # Single failed_type - group by the type
                failed_type = failed_types[0]
                if failed_type not in grouped_by_type:
                    grouped_by_type[failed_type] = {}
                grouped_by_type[failed_type][cat_name] = cat_info
                logger.info(f"Category '{cat_name}' grouped under failed_type '{failed_type}'")
            else:
                # Multiple failed_types - put in mixed group
                if "mixed_failed_type" not in grouped_by_type:
                    grouped_by_type["mixed_failed_type"] = {}
                grouped_by_type["mixed_failed_type"][cat_name] = cat_info
                logger.info(f"Category '{cat_name}' grouped under 'mixed_failed_type' with types: {failed_types}")

        # Log the grouping results
        for group_key, group_categories in grouped_by_type.items():
            logger.info(f"Group '{group_key}': {len(group_categories)} categories")

        return grouped_by_type

    def compare_with_active_icm_list(self, analysis_df, active_icm_df):
        """
        Compare the flaky failure analysis results with active ICM list to identify and remove duplicates.

        Args:
            analysis_df: DataFrame containing the flaky failure analysis results
            active_icm_df: DataFrame containing the active ICM list
            output_csv_path: Path to save the filtered results (non-duplicates)
            duplicated_csv_path: Path to save the duplicated results
        """
        logger.info("Comparing analysis results with active ICM list...")

        try:
            non_duplicated_rows = []
            duplicated_rows = []

            # Process each row in the analysis results
            for idx, analysis_row in analysis_df.iterrows():
                row_type = analysis_row.get('failed_type', '')
                logger.info(f"Processing analysis row {idx + 1}/{len(analysis_df)}: {row_type}")

                # Get the failed type from the analysis
                analysis_failed_type = analysis_row['failed_type']

                # Find all active ICM entries with the same failed type (flaky_category)
                matching_icm_rows = active_icm_df[
                    (active_icm_df['flaky_category'] == analysis_failed_type) &
                    (active_icm_df['is_flaky'] is True)
                ]

                if len(matching_icm_rows) == 0:
                    logger.info(f"No matching ICM entries found for failed_type '{analysis_failed_type}'")
                    non_duplicated_rows.append(analysis_row)
                    continue

                logger.info(f"Found {len(matching_icm_rows)} ICM entries with same "
                            f"failed_type '{analysis_failed_type}'")

                # Use LLM to check if the analysis result is a duplicate
                is_duplicate = self._check_duplicate_with_llm(analysis_row, matching_icm_rows)

                if is_duplicate:
                    logger.info("Analysis row identified as duplicate, moving to duplicated list")
                    duplicated_rows.append(analysis_row)
                else:
                    logger.info("Analysis row is unique, keeping in main results")
                    non_duplicated_rows.append(analysis_row)

            # Save the filtered results
            if non_duplicated_rows:
                non_duplicated_df = pd.DataFrame(non_duplicated_rows)
                logger.info(f"Saved {len(non_duplicated_df)} non-duplicated results to DataFrame")
            else:
                # Create empty DataFrame with same columns
                empty_df = pd.DataFrame(columns=analysis_df.columns)
                non_duplicated_df = empty_df
                logger.info("No non-duplicated results found!")

            # Save the duplicated results
            if duplicated_rows:
                duplicated_df = pd.DataFrame(duplicated_rows)
                logger.info(f"Saved {len(duplicated_df)} duplicated results to DataFrame")
            else:
                # Create empty DataFrame with same columns
                empty_df = pd.DataFrame(columns=analysis_df.columns)
                duplicated_df = empty_df
                logger.info("No duplicated results found!")

            return non_duplicated_df, duplicated_df

        except Exception as e:
            logger.error(f"Error during comparison with active ICM list: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            raise

    def _check_duplicate_with_llm(self, analysis_row, matching_icm_rows):
        """
        Use LLM to check if an analysis result is a duplicate of existing ICM entries.
        Uses batch processing when there are more than 8 matching ICM rows.

        Args:
            analysis_row: Single row from analysis results
            matching_icm_rows: DataFrame of ICM entries with same failed_type

        Returns:
            bool: True if duplicate, False if unique
        """
        try:
            # If we have 8 or fewer ICM entries, process in single batch
            if len(matching_icm_rows) <= configuration["ai_analysis"]["duplicate_batch_size"]:
                logger.info(f"Processing {len(matching_icm_rows)} ICM entries in single batch")
                return self._check_duplicate_single_batch(analysis_row, matching_icm_rows)

            # For more than 8 entries, use batch processing to avoid losing potential duplicates
            logger.info(f"Processing {len(matching_icm_rows)} ICM entries in batches "
                        f"due to large size")

            # Convert DataFrame rows to list of dictionaries for batch processing
            icm_list = []
            for _, icm_row in matching_icm_rows.iterrows():
                icm_dict = {
                    'AI_flaky_category': icm_row.get('AI_flaky_category', 'N/A'),
                    'ModulePath': icm_row['ModulePath'],
                    'TestCase': icm_row['TestCase'],
                    'Branch': icm_row['Branch'],
                    'FailureSummary': icm_row['FailureSummary']
                }
                icm_list.append(icm_dict)

            # Process in batches of 8 with early termination on duplicate found
            batch_size = configuration["ai_analysis"]["duplicate_batch_size"]
            total_batches = (len(icm_list) + batch_size - 1) // batch_size

            for i in range(0, len(icm_list), batch_size):
                batch = icm_list[i:i + batch_size]
                batch_num = i // batch_size + 1

                logger.info(f"Processing duplicate check batch {batch_num}/{total_batches} with "
                            f"{len(batch)} ICM entries")

                try:
                    batch_result = self._check_duplicate_batch(batch, analysis_row)

                    # Early termination: if duplicate found, return immediately
                    if batch_result and batch_result.get('is_duplicate', False):
                        logger.info(f"Found duplicate in batch {batch_num}, skipping remaining "
                                    f"{total_batches - batch_num} batches")
                        logger.info(f"Duplicate explanation: {batch_result.get('explanation', '')[:200]}...")
                        return True

                except Exception as e:
                    logger.error(f"Error processing duplicate check batch {batch_num}: {e}")
                    logger.error(f"Full traceback:\n{traceback.format_exc()}")
                    # Continue with other batches even if one fails
                    continue

            # No duplicates found in any batch
            logger.info("No duplicates found after processing all batches")
            return False

        except Exception as e:
            logger.error(f"Error in LLM duplicate check: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            logger.warning("Assuming UNIQUE due to LLM error")
            return False

    def _check_duplicate_single_batch(self, analysis_row, matching_icm_rows):
        """
        Check for duplicates against a single batch of ICM entries (10 or fewer).

        Args:
            analysis_row: Single row from analysis results
            matching_icm_rows: DataFrame of ICM entries with same failed_type

        Returns:
            bool: True if duplicate, False if unique
        """
        try:
            # Create prompt for duplicate detection
            prompt = f"""You are analyzing test failure patterns to identify duplicates.

ANALYSIS RESULT TO CHECK:
Category: {analysis_row['AI_flaky_category']}
Failed Type: {analysis_row['failed_type']}
Branch: {analysis_row['branch']}
Summary: {analysis_row['failure_summary']}

EXISTING ICM ENTRIES WITH SAME FAILED TYPE:
"""

            # Add matching ICM entries to prompt
            for i, (_, icm_row) in enumerate(matching_icm_rows.iterrows()):
                prompt += f"\nICM Entry {i+1}:\n"
                prompt += f"  AI Category: {icm_row.get('AI_flaky_category', 'N/A')}\n"
                prompt += f"  Title: {icm_row['Title']}\n"
                prompt += f"  Branch: {icm_row['Branch']}\n"
                prompt += f"  Summary: {icm_row['FailureSummary']}...\n"

            prompt += """
TASK: Determine if the ANALYSIS RESULT represents the same failure pattern as any of the EXISTING ICM ENTRIES.

Consider these factors:
1. Root cause similarity (same underlying issue)
2. Error message patterns

Respond with exactly one of:
- "DUPLICATE" if the analysis result represents the same failure pattern as existing ICM entries
- "UNIQUE" if the analysis result represents a new/different failure pattern

Provide a brief explanation for your decision.
"""

            system_message = ("You are an expert at analyzing software test failure patterns to identify "
                              "duplicates based on root causes and error patterns.")

            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]

            logger.info(f"Checking for duplicates using LLM for category '{analysis_row['AI_flaky_category']}'")
            # logger.info(f"Prompt: {prompt}")
            # logger.info(f"System Message: {system_message}")
            response = self._call_llm_with_retry(messages)

            # Parse the response
            if "DUPLICATE" in response.upper():
                logger.info(f"LLM identified as DUPLICATE: {response}")
                return True
            elif "UNIQUE" in response.upper():
                logger.info(f"LLM identified as UNIQUE: {response}")
                return False
            else:
                logger.warning(f"LLM response unclear, assuming UNIQUE: {response}")
                return False

        except Exception as e:
            logger.error(f"Error in single batch duplicate check: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return False

    def _check_duplicate_batch(self, icm_batch, analysis_row):
        """
        Check if analysis result is duplicate against a batch of ICM entries.

        Args:
            icm_batch: List of ICM row dictionaries to compare against
            analysis_row: Single analysis row to check

        Returns:
            dict: Result with is_duplicate flag and explanation
        """
        try:
            # Create prompt for duplicate detection with this batch
            prompt = f"""You are analyzing test failure patterns to identify duplicates.

ANALYSIS RESULT TO CHECK:
Category: {analysis_row['AI_flaky_category']}
Failed Type: {analysis_row['failed_type']}
Summary: {analysis_row['failure_summary']}

EXISTING ICM ENTRIES WITH SAME FAILED TYPE (Batch):
"""

            # Add ICM entries from this batch to prompt
            for i, icm_row in enumerate(icm_batch):
                prompt += f"\nICM Entry {i+1}:\n"
                ai_category = icm_row.get('AI_flaky_category', 'N/A')
                prompt += f"  AI Category: {ai_category}\n"
                prompt += f"  Summary: {icm_row['FailureSummary']}\n"

            prompt += f"""
TASK: Determine if the ANALYSIS RESULT represents the same failure pattern as ANY of the {len(icm_batch)} \
EXISTING ICM ENTRIES in this batch.

Consider these factors:
1. Root cause similarity (same underlying issue)
2. Error message patterns

Respond with exactly one of:
- "DUPLICATE" if the analysis result represents the same failure pattern as any existing ICM entry
- "UNIQUE" if the analysis result represents a new/different failure pattern from all entries in this batch

Provide a brief explanation for your decision.
"""

            system_message = ("You are an expert at analyzing software test failure patterns to identify "
                              "duplicates based on root causes and error patterns.")

            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]

            logger.info(f"Checking duplicates for batch of {len(icm_batch)} ICM entries")
            response = self._call_llm_with_retry(messages)

            # Parse the response
            if "DUPLICATE" in response.upper():
                logger.info("LLM identified as DUPLICATE in batch")
                return {"is_duplicate": True, "explanation": response}
            elif "UNIQUE" in response.upper():
                logger.info("LLM identified as UNIQUE in batch")
                return {"is_duplicate": False, "explanation": response}
            else:
                logger.warning("LLM response unclear in batch, assuming UNIQUE")
                return {"is_duplicate": False, "explanation": response}

        except Exception as e:
            logger.error(f"Error in batch duplicate check: {e}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return {"is_duplicate": False, "explanation": f"Error: {e}"}

    def _process_llm_in_batches(self, items, batch_size, process_function, *args, **kwargs):
        """
        Generic function to process items in batches for LLM operations.

        Args:
            items: List of items to process
            batch_size: Size of each batch
            process_function: Function to call for each batch
            *args, **kwargs: Additional arguments to pass to process_function

        Returns:
            Combined results from all batches
        """
        logger.info(f"Processing {len(items)} items in batches of {batch_size}")

        all_results = []

        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(items) + batch_size - 1) // batch_size

            logger.info(f"Processing batch {batch_num}/{total_batches} with {len(batch)} items")

            try:
                batch_result = process_function(batch, *args, **kwargs)
                if batch_result:
                    all_results.append(batch_result)
            except Exception as e:
                logger.error(f"Error processing batch {batch_num}: {e}")
                logger.error(f"Full traceback:\n{traceback.format_exc()}")
                # Continue with other batches even if one fails
                continue

        return all_results

    def run_ai_flaky_analysis(self, analyzer):
        """
        Run AI-based flaky case analysis workflow.

        Args:
            analyzer: DataAnalyzer instance for collecting flaky failure data

        Returns:
            tuple: (non_duplicated_df, duplicated_df, ai_kusto_df) from AI analysis results
                - ai_kusto_df: DataFrame with history statistics in kusto format, or None if no data
                - duplicated_df: DataFrame with duplicated AI-analyzed cases
        """
        logger.info("=================Starting AI-based flaky case analysis=================")

        try:
            analyzer.common_trigger = False
            analyzer.legacy_trigger = False
            analyzer.flaky_trigger = True
            analyzer.consistent_trigger = False
            # Collect flaky failures for AI analysis
            kusto_data_list = []
            flaky_df_for_ai = analyzer.collect_flaky_failure(query_testbed=True)

            if not flaky_df_for_ai.empty:
                # Run AI analysis on flaky cases
                logger.info(f"Running AI analysis on {len(flaky_df_for_ai)} flaky failure cases")
                ai_analysis_results = self.analyze_flaky_cases(flaky_df_for_ai)
                # Save AI analysis results to CSV
                ai_analysis_results.to_csv(AI_FLAKY_ANALYSIS_CSV, index=True)
                logger.info(f"AI analysis results saved to: {AI_FLAKY_ANALYSIS_CSV}")

                if ai_analysis_results is not None and not ai_analysis_results.empty:
                    logger.info(f"AI analysis completed successfully. Found {len(ai_analysis_results)} analyzed cases")
                    # Compare with active ICM list
                    # Read active ICM list if not already loaded in analyzer
                    logger.info("Comparing AI analysis results with active ICM list")
                    non_duplicated_df, duplicated_df = self.compare_with_active_icm_list(
                        ai_analysis_results, analyzer.active_icm_df
                    )
                    logger.info(f"Comparison complete. Non-duplicated: {len(non_duplicated_df)}, "
                                f"Duplicated: {len(duplicated_df)}")
                    duplicated_df.to_csv(AI_FLAKY_DUPLICATED_CSV, index=True)
                    if non_duplicated_df is not None:
                        logger.info(f"Found {len(non_duplicated_df)} non-duplicated AI-analyzed flaky cases")
                        logger.info(f"Found {len(duplicated_df) if duplicated_df is not None else 0} "
                                    f"duplicated AI-analyzed cases")
                        # Save non-duplicated results to CSV
                        non_duplicated_df.to_csv(AI_FLAKY_CATEGORIZED_CSV, index=True)
                        # Log sample results
                        if len(non_duplicated_df) > 0:
                            logger.info("Sample non-duplicated AI-analyzed cases:")
                            for idx, row in non_duplicated_df.head(3).iterrows():
                                logger.info(f"  - Category: {row.get('AI_flaky_category', 'N/A')}, "
                                            f"Type: {row.get('failed_type', 'N/A')}")
                                logger.info(f"    Summary: {row.get('failure_summary', 'N/A')[:100]}...")

                        # Calculate history statistics for each non-duplicated case
                        logger.info("Calculating history statistics for AI-analyzed cases...")

                        for idx, row in non_duplicated_df.iterrows():
                            try:
                                module_path = row['module_path']
                                testcase = row['test_case']
                                branch = row['branch']
                                branch_name = module_path + '.' + testcase + "#" + branch
                                # Create case_info_dict for search_and_parse_history_results
                                case_info_dict = {
                                    'case_branch': branch_name,
                                    'is_module_path': False,  # AI cases are typically test cases, not module paths
                                    'is_common_summary': False,
                                    'failed_type': row.get('failed_type', ''),
                                    'AI_flaky_category': row.get('AI_flaky_category', ''),
                                    'summary': row.get('failure_summary', '')
                                }

                                # Calculate history statistics
                                history_testcases, history_case_df = analyzer.search_and_parse_history_results(
                                    case_info_dict)

                                # Generate kusto data format
                                kusto_data = analyzer.generate_kusto_data(case_info_dict, history_testcases,
                                                                          history_case_df)

                                # Add correlate_cases to each item in kusto_data (which is a list)
                                for kusto_item in kusto_data:
                                    logger.info(f"Adding correlate_cases to kusto item for case {idx}")
                                    kusto_item['correlate_cases'] = row['correlate_cases']

                                kusto_data_list.extend(kusto_data)

                            except Exception as e:
                                logger.warning(f"Failed to calculate history statistics for case {idx}: {str(e)}")
                                logger.error(f"Full traceback:\n{traceback.format_exc()}")
                                continue

                        if kusto_data_list:
                            logger.info(f"Successfully calculated history statistics for "
                                        f"{len(kusto_data_list)} AI-analyzed cases")
                            # Convert list of dicts to DataFrame
                            ai_kusto_df = pd.DataFrame(kusto_data_list)
                            ai_kusto_df.to_csv(AI_FLAKY_AFTER_DEDUPLICATION_CSV, index=True)

                            return kusto_data_list, duplicated_df.to_dict(orient='records')
                        else:
                            logger.warning("No kusto data generated for AI-analyzed cases")
                            return kusto_data_list, duplicated_df.to_dict(orient='records')
                    else:
                        logger.warning("AI comparison with active ICM list returned no results")
                        return None, None
                else:
                    logger.warning("AI analysis returned no results")
                    return None, None
            else:
                logger.warning("No flaky failure cases found for AI analysis")
                return None, None

        except Exception as e:
            logger.error(f"Error during AI-based flaky case analysis: {str(e)}")
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            logger.info("Continuing with regular analysis workflow...")
            return None, None

        finally:
            logger.info("=================AI-based flaky case analysis completed=================")
