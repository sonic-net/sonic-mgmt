**Before running script:**
1. Please install dependencies in requirements.txt
2. You can use the command "pip install -r requirements.txt"
3. Fetch the personal access token from GitHub
https://docs.github.com/en/github/authenticating-to-github/keeping-your-account-and-data-secure/creating-a-personal-access-token
Make sure to select all scopes while creating token. 
TokenAPI has been deprecated hence this manual process.

**How to run the script?**
python githubautomation.py put_the_token_here

**After running script:**
You will find below files generated in the same directoy you ran script
1. bugslist.csv
2. bugslist.json


Note:
Running this too many times will lead to below error
**Exception**: {"message":"API rate limit exceeded for 172.27.147.152. (But here's the good news: Authenticated requests get a higher rate limit. Check out the documentation for more details.)
An alternate to increase the limit should be looked on.
