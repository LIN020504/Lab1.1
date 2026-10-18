\# Lab1.1 — Security Projects



A collection of security and programming lab projects.



\## Projects



\### Security REST API



Location: `security-rest-api/`



A Python REST API project demonstrating:



\- User registration and login

\- JWT-based authentication

\- Password hashing

\- Protected API endpoints

\- Automated tests with pytest

\- Static Application Security Testing (SAST) with Bandit

\- Software Composition Analysis (SCA) with pip-audit



\## Run locally



Use Python 3.11 or a compatible version.



Install dependencies:



```bash

python -m pip install -r security-rest-api/requirements.txt

```



Set a development-only JWT secret before starting the API.



Windows CMD:



```bat

set JWT\_SECRET=replace-with-a-local-development-secret

python -m uvicorn main:app --reload

```



Run these commands from the `security-rest-api` directory.



\## Automated checks



GitHub Actions runs tests and security scans on pushes and pull requests.



\- pytest: automated tests

\- Bandit: Python static security analysis

\- pip-audit: dependency vulnerability checks



\## Security notes



Do not commit real secrets, virtual environments, or local database files. The JWT secret used in CI is for testing only and must not be used in production.



