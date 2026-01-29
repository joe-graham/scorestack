# Deploying checks to all teams

Because of the subnets used for team10, teams1-9 and 10 need to be added to the scoring engine in tiers. To deploy to all teams and ensure IP addressing errors don't occur, follow these steps:

1. Copy whatever changes you made to the existing check configurations onto the jump box, which as of writing is at 129.21.246.209.
2. Modify the CHECK_FOLDER variable in add-team.sh to point to `checks/teams1-9`.
3. Run `add-team.sh team01 team02 team03 team04 team05 team06 team07 team08 team09` in the root of the repository. This will take a little over a minute to add all the necessary checks for each team.
4. Change the CHECK_FOLDER variable in add-team.sh to point to `checks/team10`. NOTE: this *isn't* pluralized, I almost typoed this just now by forgetting to remove the 's' in 'teams'.
5. Run `add-team.sh team10`. This should take less time than the first run but will still take about 30 seconds.
6. Run `add-tor-checks.sh`. This will add the Tor related checks.
7. Run `set_team_creds.sh team_creds.txt` to ensure the team accounts passwords match their VDI logins.
8. Confirm at `https://scoring.newscrier.org` from a web browser that can access the competition infrastructure that team10 has no weird errors caused by IP addresses that look like "172.17.210.2" or "172.17.410.2".