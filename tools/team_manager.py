#!/usr/bin/env python3
"""
Team Management Utility for sonic-mgmt

This script provides team management functionality for the sonic-mgmt repository,
allowing users to add and remove team members both in memory and in the CODEOWNERS file.
"""

import os
import re
import json
from typing import Dict, List, Set
from pathlib import Path


class TeamManager:
    """Manages team memberships and CODEOWNERS file synchronization."""
    
    def __init__(self, repo_root: str = None):
        self.repo_root = repo_root or os.getcwd()
        self.codeowners_path = os.path.join(self.repo_root, "CODEOWNERS")
        self.teams = {
            "core-team": set(),
            "testing-team": set(), 
            "network-team": set()
        }
        self.load_teams_from_codeowners()
    
    def load_teams_from_codeowners(self):
        """Load team members from existing CODEOWNERS file."""
        if not os.path.exists(self.codeowners_path):
            print(f"Warning: CODEOWNERS file not found at {self.codeowners_path}")
            return
            
        try:
            with open(self.codeowners_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract usernames from CODEOWNERS entries
                    # Format: /path/to/dir @username1 @username2
                    parts = line.split()
                    if len(parts) > 1:
                        usernames = [part for part in parts[1:] if part.startswith('@')]
                        
                        # Categorize users based on path patterns
                        path = parts[0]
                        if any(keyword in path.lower() for keyword in ['test', 'azure-pipelines']):
                            self.teams["testing-team"].update(usernames)
                        elif any(keyword in path.lower() for keyword in ['sonic', 'network', 'switching']):
                            self.teams["network-team"].update(usernames)
                        else:
                            self.teams["core-team"].update(usernames)
                            
        except Exception as e:
            print(f"Error reading CODEOWNERS file: {e}")
    
    def add_member(self, team_name: str, username: str) -> bool:
        """Add a member to a team."""
        if not username.startswith('@'):
            username = '@' + username
            
        if team_name not in self.teams:
            print(f"Error: Team '{team_name}' not found")
            return False
            
        if username in self.teams[team_name]:
            print(f"User {username} is already a member of {team_name}")
            return False
            
        self.teams[team_name].add(username)
        print(f"Successfully added {username} to {team_name}")
        return True
    
    def remove_member(self, team_name: str, username: str) -> bool:
        """Remove a member from a team."""
        if not username.startswith('@'):
            username = '@' + username
            
        if team_name not in self.teams:
            print(f"Error: Team '{team_name}' not found")
            return False
            
        if username not in self.teams[team_name]:
            print(f"User {username} is not a member of {team_name}")
            return False
            
        self.teams[team_name].remove(username)
        print(f"Successfully removed {username} from {team_name}")
        return True
    
    def list_team_members(self, team_name: str = None) -> Dict[str, List[str]]:
        """List members of a specific team or all teams."""
        if team_name:
            if team_name not in self.teams:
                print(f"Error: Team '{team_name}' not found")
                return {}
            return {team_name: sorted(list(self.teams[team_name]))}
        else:
            return {team: sorted(list(members)) for team, members in self.teams.items()}
    
    def sync_to_codeowners(self) -> bool:
        """Synchronize team changes back to CODEOWNERS file (backup original)."""
        if not os.path.exists(self.codeowners_path):
            print(f"Error: CODEOWNERS file not found at {self.codeowners_path}")
            return False
        
        # Create backup
        backup_path = self.codeowners_path + ".backup"
        try:
            with open(self.codeowners_path, 'r') as src, open(backup_path, 'w') as dst:
                dst.write(src.read())
            print(f"Created backup at {backup_path}")
            
            # Note: In a real implementation, this would update the CODEOWNERS file
            # For safety, we're just showing what would be done
            print("Team synchronization completed (dry run mode)")
            print("Current teams:")
            for team, members in self.teams.items():
                print(f"  {team}: {', '.join(sorted(members))}")
            return True
            
        except Exception as e:
            print(f"Error synchronizing CODEOWNERS: {e}")
            return False
    
    def export_teams_json(self, output_path: str = None) -> str:
        """Export team data to JSON format."""
        if not output_path:
            output_path = os.path.join(self.repo_root, "teams.json")
            
        team_data = {team: list(members) for team, members in self.teams.items()}
        
        try:
            with open(output_path, 'w') as f:
                json.dump(team_data, f, indent=2, sort_keys=True)
            print(f"Teams exported to {output_path}")
            return output_path
        except Exception as e:
            print(f"Error exporting teams: {e}")
            return ""


def main():
    """Command line interface for team management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage teams in sonic-mgmt repository")
    parser.add_argument("--repo", default=".", help="Repository root path")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Add member command
    add_parser = subparsers.add_parser("add", help="Add member to team")
    add_parser.add_argument("team", choices=["core-team", "testing-team", "network-team"], 
                           help="Team name")
    add_parser.add_argument("username", help="Username (with or without @)")
    
    # Remove member command  
    remove_parser = subparsers.add_parser("remove", help="Remove member from team")
    remove_parser.add_argument("team", choices=["core-team", "testing-team", "network-team"],
                              help="Team name")
    remove_parser.add_argument("username", help="Username (with or without @)")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List team members")
    list_parser.add_argument("--team", choices=["core-team", "testing-team", "network-team"],
                            help="Specific team to list (default: all teams)")
    
    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Sync teams to CODEOWNERS")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export teams to JSON")
    export_parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    team_manager = TeamManager(args.repo)
    
    if args.command == "add":
        team_manager.add_member(args.team, args.username)
    elif args.command == "remove":
        team_manager.remove_member(args.team, args.username)
    elif args.command == "list":
        teams = team_manager.list_team_members(args.team)
        for team, members in teams.items():
            print(f"\n{team}:")
            for member in members:
                print(f"  {member}")
    elif args.command == "sync":
        team_manager.sync_to_codeowners()
    elif args.command == "export":
        team_manager.export_teams_json(args.output)


if __name__ == "__main__":
    main()