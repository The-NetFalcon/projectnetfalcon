# projectnetfalcon

## Backend API

The backend API is located in the `backend_api` folder. It is a Flask application with a SQLite database and a PDF export endpoint.

### Run locally

1. Open a terminal and navigate to the backend folder:
   ```powershell
   cd backend_api
   ```
2. (Optional but recommended) Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
3. Install dependencies:
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```
4. Start the backend service:
   ```powershell
   python app.py
   ```
5. The service will listen on `http://127.0.0.1:5000`.

### Available routes

- `GET /` - health check
- `GET /cases` - list all cases
- `POST /cases` - create a new case
- `GET /cases/<id>` - retrieve a case by ID
- `PUT /cases/<id>` - update a case by ID
- `DELETE /cases/<id>` - delete a case by ID
- `GET /export-pdf` - export all cases to PDF
- `GET /export-pdf?case_id=<id>` - export a single case to PDF

### Run with Docker

From the repository root, build the image and run it:

```powershell
docker build -t projectnetfalcon-backend backend_api
docker run -p 5000:5000 projectnetfalcon-backend
```

The backend will then be available at `http://127.0.0.1:5000`.
