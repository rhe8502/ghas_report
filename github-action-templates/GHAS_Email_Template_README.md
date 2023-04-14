# This GitHub Action sends daily email notifications with attached CSV files containing Github Advanced Security (GHAS) reports

## Workflow

The workflow is defined in the `.github/workflows/email_ghas_reports.yml` file.

### Triggers

The workflow is scheduled to run every day at 00:00 UTC.

### Job: `run_script_and_send_email`

The job runs on the latest version of Ubuntu and consists of the following steps:

1. Check out the repository
2. Clone the `ghas_report` repository
3. Set up Python 3.x
4. Install dependencies
5. Generate a JSON configuration file
6. Run the Python script `ghas_report.py`
7. Send an email with the generated CSV files as attachments

## Configuration

### Secrets

You need to set up the following secrets in your GitHub repository:

- `GH_API_KEY`: Your GitHub API key
- `EMAIL_USERNAME`: Your email username (e.g., Gmail address)
- `EMAIL_PASSWORD`: Your email password or App password (if using Gmail)

### JSON Configuration File

The JSON configuration file (`ghas_config.json`) must be configured with your project details:

- `YOUR_PROJECT`: Replace with your project's name
- `OWNER`: Replace with the repository owner's username
- `YOUR_ORG`: Replace with your organization's name
- `YOUR_REPO`: Replace with your repository's name

### Email Configuration

Modify the following fields in the `Send CSV files via email` step:

- `to`: Replace `your_email@example.com` with the recipient's email address
- `from`: Replace `GitHub Action <sender_email@gmail.com>` with the sender's name and email address

## Usage

To use this GitHub Action in your repository, copy the `.github/workflows/email_ghas_reports.yml` file to your repository's `.github/workflows` directory. Update the configuration file and email settings as needed.
