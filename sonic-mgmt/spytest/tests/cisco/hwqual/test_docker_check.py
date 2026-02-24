#!/usr/bin/env python3
"""
Docker Container Validation for Platform EDVT Testing

This script parses 'docker ps' output and validates that all required Docker containers
from the platform_edvt_cfg.py configuration are running.
"""
import re
import pytest
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_edvt_cfg import platform_edvt_cfg
from apis.common.sonic_hooks import SonicHooks

@pytest.fixture(scope="module", autouse=True)
def docker_check_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** DOCKER Check *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username + "/"
    CfgDataG.dut = TBDataG.D1

    yield
    pass


def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)


def parse_docker_ps_output(docker_output):
    """
    Parse 'docker ps' output and extract container names
    
    Args:
        docker_output (str): Raw output from 'docker ps' command
        
    Returns:
        dict: Parsed docker information with container names and details
    """
    docker_data = {
        'running_containers': [],
        'container_details': [],
        'total_count': 0
    }
    
    try:
        lines = docker_output.strip().split('\n')
        
        # Find header line to determine column positions
        header_line = None
        for line in lines:
            if 'CONTAINER ID' in line and 'NAMES' in line:
                header_line = line
                break
        
        if not header_line:
            st.error("Could not find header line in docker ps output")
            return docker_data
        
        # Find the position of NAMES column
        names_start = header_line.find('NAMES')
        if names_start == -1:
            st.error("Could not find NAMES column in docker ps output")
            return docker_data
        
        # Parse container data
        for line in lines:
            line = line.strip()
            if not line or 'CONTAINER ID' in line:
                continue
                
            # Extract container name (last column)
            container_name = line[names_start:].strip()
            if container_name:
                docker_data['running_containers'].append(container_name)
                
                # Extract other details
                parts = line.split()
                if len(parts) >= 6:
                    container_info = {
                        'container_id': parts[0],
                        'image': parts[1],
                        'created': parts[3] + ' ' + parts[4],
                        'status': parts[5] + ' ' + parts[6],
                        'name': container_name
                    }
                    docker_data['container_details'].append(container_info)
        
        docker_data['total_count'] = len(docker_data['running_containers'])
        return docker_data
        
    except Exception as e:
        st.error(f"Error parsing docker ps output: {e}")
        return docker_data

def validate_docker_containers(docker_output, required_containers):
    """
    Validate that all required Docker containers are running
    
    Args:
        docker_output (str): Raw output from 'docker ps' command
        required_containers (list): List of required container names
        
    Returns:
        dict: Validation results
    """
    validation_result = {
        'overall_valid': True,
        'running_containers': [],
        'missing_containers': [],
        'extra_containers': [],
        'total_required': len(required_containers),
        'total_running': 0,
        'errors': [],
        'warnings': []
    }
    
    try:
        # Parse docker output
        docker_data = parse_docker_ps_output(docker_output)
        running_containers = docker_data['running_containers']
        validation_result['total_running'] = len(running_containers)
        validation_result['running_containers'] = running_containers
        
        # Check for missing containers
        missing = []
        for required in required_containers:
            if required not in running_containers:
                missing.append(required)
        
        validation_result['missing_containers'] = missing
        
        # Check for extra containers (not in required list)
        extra = []
        for running in running_containers:
            if running not in required_containers:
                extra.append(running)
        
        validation_result['extra_containers'] = extra
        
        # Overall validation
        if missing:
            validation_result['overall_valid'] = False
            validation_result['errors'].append(f"Missing containers: {', '.join(missing)}")
        
        if extra:
            validation_result['warnings'].append(f"Extra containers running: {', '.join(extra)}")
        
        return validation_result
        
    except Exception as e:
        validation_result['overall_valid'] = False
        validation_result['errors'].append(f"Error during validation: {e}")
        return validation_result

def get_docker_containers_from_device(dut):
    """
    Get running Docker containers from device using spytest
    
    Args:
        dut: Device under test
        
    Returns:
        str: Raw docker ps output or None if failed
    """
    try:
        # Try different docker commands
        commands = [
            "docker ps",
        ]
        
        for cmd in commands:
            try:
                output = st.config(dut, cmd)
                if output and "CONTAINER ID" in output:
                    return output
            except:
                continue
        
        st.error("Could not retrieve docker containers from device")
        return None
        
    except Exception as e:
        st.error(f"Error getting docker containers: {e}")
        return None

def verify_docker_containers_validation(dut, required_containers=None):
    """
    Verify Docker containers validation on platform
    
    Args:
        dut: Device under test
        required_containers (list, optional): List of required containers.
                                            Uses docker_check from platform_edvt_cfg if None
        
    Returns:
        bool: True if all required containers are running, False otherwise
    """
    try:
        # Use docker_check from platform_edvt_cfg if not provided
        if required_containers is None:
            from tests.cisco.hwqual.platform_edvt_cfg import docker_check
            required_containers = docker_check
        
        st.log("=" * 60)
        st.log("DOCKER CONTAINERS VALIDATION")
        st.log("=" * 60)
        
        # Get docker containers from device
        docker_output = get_docker_containers_from_device(dut)
        if not docker_output:
            st.error("Failed to get docker containers from device")
            return False
        
        # Validate containers
        validation_result = validate_docker_containers(docker_output, required_containers)
        
        # Log results
        st.log(f"Required Containers: {validation_result['total_required']}")
        st.log(f"Running Containers: {validation_result['total_running']}")
        
        st.log("\nRunning Containers:")
        for container in validation_result['running_containers']:
            status = "✓" if container in required_containers else "?"
            st.log(f"  {status} {container}")
        
        if validation_result['missing_containers']:
            st.error("\nMissing Required Containers:")
            for missing in validation_result['missing_containers']:
                st.error(f"  ✗ {missing}")
        
        if validation_result['extra_containers']:
            st.log("\nExtra Containers (not required):")
            for extra in validation_result['extra_containers']:
                st.log(f"  ? {extra}")
        
        # Overall result
        if validation_result['overall_valid']:
            st.log("\n✓ All required Docker containers are running")
            return True
        else:
            st.error("\n✗ Docker container validation FAILED")
            for error in validation_result['errors']:
                st.error(f"  Error: {error}")
            return False
            
    except Exception as e:
        st.error(f"Error during Docker container validation: {e}")
        return False

def test_docker_check(CfgDataG, docker_check, result):
    st.log(f"{CfgDataG.logprefix}: Executing {docker_check} check")

    result = verify_docker_containers_validation(CfgDataG.dut)
    if result:
        st.report_pass(f"test_case_passed", "All required Docker containers are running")
    else:
        st.report_fail(f"test_case_failed", "Docker container validation failed - missing required containers")
        return False

    return True
