# Render Deployment

This project can run on Render as a Python `Web Service`.

## What was prepared

- `app.py` now uses `register_app/templates` and `register_app/static` explicitly.
- `/healthz` was added for Render health checks.
- The app now supports either `DATABASE_URL` or the existing `MYSQL*` environment variables.
- Uploads and ML model artifacts can be redirected with `UPLOAD_FOLDER` and `MODEL_ARTIFACT_DIR`.
- `render.yaml` was added for Render Blueprints.

## Recommended Render setup

1. Push this repository to GitHub, GitLab, or Bitbucket.
2. In Render, create a new Blueprint or Web Service from the repo.
3. Use the Python runtime.
4. Build command:

```bash
pip install -r requirements.txt
```

5. Start command:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```

6. Set `PYTHON_VERSION=3.11.11`.

## Environment variables

Use either:

- `DATABASE_URL`

or:

- `MYSQLHOST`
- `MYSQLPORT`
- `MYSQLUSER`
- `MYSQLPASSWORD`
- `MYSQLDATABASE`

Also set:

- `SECRET_KEY`
- `MAIL_USERNAME`
- `MAIL_PASSWORD`
- `MAIL_DEFAULT_SENDER`

Optional:

- `UPLOAD_FOLDER`
- `MODEL_ARTIFACT_DIR`

If you attach a Render persistent disk, point the optional variables to the disk mount path.

## Database note

Render does not provide managed MySQL. Use an external MySQL database service, or migrate this app to Postgres before deploying.

The existing `database.sql` file contains historical commands and manual fixes, so it is not a clean first-time bootstrap script. For deployment, export a fresh dump from your working local MySQL database and import that into your hosted MySQL service.

## File storage note

Without a persistent disk, uploaded product images and trained model files are ephemeral on Render and will be lost when the service restarts or redeploys.
