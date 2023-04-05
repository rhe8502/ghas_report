# GHAS Reporting

## Description

The GHAS Reporting project consists of two Python scripts: `ghas_report.py` and `ghas_enc_key.py`.

The primary script, `ghas_report.py`, is designed to retrieve various types of GitHub Advanced Security (GHAS) alerts for specified organizations or repositories and generate a report based on the provided options. The output formats supported are CSV and JSON.

The main goal of this script is to aid vulnerability management and support development and security teams by saving time and providing valuable insights into the security status of their projects.

The `ghas_enc_key.py` script is primarily used for the first-time setup and changing of the GitHub API key, which is stored in encrypted format in the **ghas_conf.json** configuration file. This script ensures the secure storage of the API key and allows for easy updates whenever needed.

### GitHub Advanced Security (GHAS)

GitHub Advanced Security is a suite of security tools provided by GitHub to help protect your code and detect vulnerabilities before they reach production. GHAS includes Code scanning, Secret scanning, and Dependabot alerts. For more information, visit [GitHub Advanced Security](https://docs.github.com/en/github-ae@latest/code-security).

### Prerequisites

To use these scripts, you will need:

1. Python 3.x installed on your system.
2. A GitHub API key with the appropriate permissions.

To generate a GitHub API key for an individual repository, follow the instructions [here](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token).

For enterprise repositories with Single Sign-On (SSO), follow the instructions [here](https://docs.github.com/en/enterprise-cloud@latest/authentication/authenticating-with-saml-single-sign-on/authorizing-a-personal-access-token-for-use-with-saml-single-sign-on).

### Installation Instructions

1. Clone the repository or download the zip file containing the project files.
2. Extract the files to a directory of your choice.
3. Open a terminal or command prompt and navigate to the directory containing the extracted files.
4. Ensure you have Python 3.x installed on your system. You can verify this by running `python --version` or `python3 --version` in the terminal or command prompt. If you don't have Python 3.x installed, download and install it from the [official Python website](https://www.python.org/downloads/).
5. In the terminal or command prompt, run the following command to install the required dependencies:

``` bash
pip install -r requirements.txt
```

This command installs the necessary packages listed in the `requirements.txt` file.

6. After the dependencies are installed, run the `ghas_enc_key.py` script to set up the GitHub API key for the first time:

```bash  
python3 ghas_enc_key.py --api-key
```

 Follow the prompts to enter your GitHub API key. The script will store the API key securely in the `ghas_conf.json` configuration file.

7. You are now ready to use the `ghas_report.py` script to generate reports. For usage instructions and examples, refer to the Usage Examples section in the documentation.

### Usage Examples

Before using `ghas_report.py`, you must run the `ghas_enc_key.py` script to set up your API key. This script securely stores your GitHub API key in a JSON configuration file.

#### Example 1: Generate all alert reports in the default CSV format

```bash
python3 ghas_report.py -a
```

This command generates all alert reports, including Alert Count, Code Scanning, Secret Scanning, and Dependabot alert reports, in the default CSV format.

#### Example 2: Generate all open alerts report in JSON format

```bash
python3 ghas_report.py -a -o -wJ
```

This command generates all open alert reports, including Alert Count, Code Scanning, Secret Scanning, and Dependabot alert reports and writes the output in JSON format.

Please note that the Alert Count report lists only open alerts by default, even without specifying the `-o` option.

#### Example 3: Generate a Code Scan alert report and a Secret Scanning alert report in CSV format

```bash
python3 ghas_report.py -c -s
```

This command generates both a Code Scan alert report and a Secret Scanning alert report in the default CSV format.

#### Example 4: Generate a Dependabot alert report in all formats and specify a custom reports directory

```bash
python3 ghas_report.py -d -wA -lr /path/to/reports
```

This command generates a Dependabot alert report and writes the output to all supported formats (CSV and JSON) in a custom reports directory specified by `/path/to/reports`.

#### Example 5: Generate an open alerts report in JSON format with custom configuration and key file locations

```bash
python3 ghas_report.py -l -wJ -lc /path/to/ghas_conf.json -lk /path/to/.ghas_env
```

This command generates an Alert Count report, writes the output in JSON format, and uses custom locations for the configuration file (`/path/to/ghas_conf.json`) and the encryption key file (`/path/to/.ghas_env`).

For more usage examples and options, refer to the options sections for each script in the documentation.

#### `ghas_report.py`

| Option | Description |
| ----------- | ----------- |
| -h, --help | Show help message and exit |
|-v, --version | Show program's version number and exit |
| -a, --all | Generate all alert reports |
| -l, --alerts | Generate Alert Count report |
| -c, --codescan | Generate Code Scan alert report |
| -s, --secretscan | Generate Secret Scanning alert report |
| -d, --dependabot | Generate Dependabot alert report |
| -o, --open | Generate report(s) for open alerts only |
| -wA, --output-all | Write output to all formats at once |
| -wC, --output-csv | Write output to a CSV file (default format) |
| -wJ, --output-json | Write output to a JSON file |
| -lc \<PATH\>, --config \<PATH\> | Specify file location for the configuration file ("ghas_conf.json") |
| -lk \<PATH\>, --keyfile \<PATH\> | Specify file location for the encryption key file (".ghas_env") - overrides the location specified in the configuration file |
| -lr \<PATH\>, --reports \<PATH\> | Specify file location for the reports directory - overrides the location specified in the configuration file |

#### `ghas_enc_key.py`

| Option | Description |
| ----------- | ----------- |
| -h, --help | Show help message and exit |
| -v, --version | Show program's version number and exit |
| -a, --api-key | Prompt for a GitHub API key; replaces existing API key or generates a new config & key file if none exist (first-time setup) |
| -lc \<PATH\>, --config \<PATH\> | Specify file location for the "ghas_report.py" configuration file ("ghas_conf.json") |
| -lk \<PATH\>, --keyfile \<PATH\> | Specify file location for the "ghas_report.py" encryption key file (".ghas_env") |
| -lr \<PATH\>, --reports \<PATH\> | Specify file location for the "ghas_report.py" reports directory |

## Configuration File

The **"ghas_config.json"** JSON configuration file is used to specify connection details, location and project information for the GitHub Advanced Security (GHAS) reporting tool.  A sample configuration file **"ghas_config_example.json""** is included in the repo. Simply rename the file to **"ghas_config.json"** and run the initial setup script to securely store your GitHub API key, then populate the file with your unique project information.

### Connection section
```json
{
    "connection": {
        "gh_api_url": "https://api.github.com",
        "gh_api_key": "GITHUB_API_KEY"
    }
}
```

This section specifies the details for connecting to the GitHub API.

- **gh_api_url:** The URL for the GitHub API.
- **gh_api_key:** Your GitHub API key.

### Location section

If no custom file locations are specified in the configuration file and no command-line options are provided, the default location for both the reports and the key file will be the script directory. The default location for report files is a folder within the script directory, which will be created with the current date as the folder name.

``` json
{
     "location": {
             "reports": "",
             "key_file": ""
         }
}
```

This section specifies the location of the reports and the encryption key file.

- **reports:** The directory path where reports will be generated. If left blank, the script will  reate a folder with the current date as its name in the script directory.
- **key_file:** The file path for the encryption key. If left blank, the script will use the default location in the script directory.

### Projects section

The `projects` section of the configuration file allows you to define your projects, including the owner, organizations, and repositories associated with each project. You can add multiple projects, each with its own set of organizations and repositories. This setup is useful when working with multiple projects, organizations, and repositories, especially in the context of a GitHub Enterprise account.

``` json
{
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
}
```

This section specifies the project information, including the owner, organizations, and repositories.

- **YOUR_PROJECT1, YOUR_PROJECT2, etc.:** The name of your project(s). You can use any name you like. This allows you to set up multiple projects with their respective organizations and repositories.
- **owner:** The owner of the project(s) on GitHub, or GitHub account owner. This is typically the organization or individual account that owns the repositories and organizations specified.
- **organizations:**  A list of the organizations that the project(s) belong to. When working with a GitHub Enterprise account, you may have multiple organizations, each with its own set of repositories.
- **repositories:** A list of the repositories that the project(s) consist of. These can be individual repositories or repositories belonging to organizations specified in the `organizations` field.

By using this structure, you can customize the script to generate reports for specific projects, organizations, and repositories, making it easier to manage security alerts across a large number of repositories and organizations.

## Troubleshooting

If you encounter any issues while using the GHAS Report scripts, try the following troubleshooting steps:

1. Ensure you have the correct permissions for your GitHub API key. The API key should have the necessary permissions to access the repositories and organizations for which you want to generate reports.
2. Double-check your file paths for the configuration, encryption key, and report files. Ensure that the paths specified are correct and the files are accessible.
3. Make sure you are using a compatible version of Python (3.x) and that all required dependencies are installed.
4. If you encounter issues with the generated reports, verify that the chosen output format is supported and that the output file can be created or written to.
5. If you are still having issues, consult the [GitHub REST API documentation](https://docs.github.com/en/rest/) and the [GitHub Advanced Security documentation](https://docs.github.com/en/github-ae@latest/code-security) for additional information.

## License

The GHAS Report project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). For more information, see the LICENSE file in the project repository.
