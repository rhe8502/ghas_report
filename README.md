## Configuration File

The **"ghas_config.json"** JSON configuration file is used to specify connection details, location and project information for the GitHub Advanced Security (GHAS) reporting tool. 

### Connection section
``` json
 "connection": {
        "gh_api_url": "https://api.github.com",
        "gh_api_key": "GITHUB_API_KEY",
        "gh_api_version": "2022-11-28"
    }
```

This section specifies the details for connecting to the GitHub API.
- **gh_api_url:** The URL for the GitHub API.
- **gh_api_key:** Your GitHub API key.
- **gh_api_version:** The version of the GitHub API to use.

### Location section
``` json
"location": {
        "reports": "",
        "key_file": ""
    }
```

This section specifies the location of the reports and the encryption key file.

- **reports:** The directory path where reports will be generated.
- **key_file:** The file path for the encryption key.

### Projects section
``` json
"projects": {
        "YOUR_PROJECT1": {
            "owner": "GITHUB_OWNER",
            "organizations": [
                "ORG1"
            ],
            "repositories": [
                "REPO1",
                "REPO2"
            ]
        },
        "YOUR_PROJECT2": {
            "owner": "GITHUB_OWNER",
            "organizations": [
                "ORG1",
                "ORG2"
            ],
            "repositories": [
                "REPO1"
            ]
        }
    }
```

This section specifies the project information, including the owner, organizations, and repositories.

- **YOUR_PROJECT1, YOUR_PROJECT2, etc.:** The name of your project(s). You can use any name you like.
- **owner:** The owner of the project(s) on GitHub, or GitHub account owner.
- **organizations:** A list of the organizations that the project(s) belong to.
- **repositories:** A list of the repositories that the project(s) consist of.