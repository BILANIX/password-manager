
# Password Manager

## Scope

A secure web-based password manager.

## Planned Features

- User registration
- Secure login
- Password vault
- AES-256-GCM encrypted password storage
- Password generator
- 2 factor authentication

## Planned Routes

| Route       |     Purpose       |
|-------------|-------------------|
| `/`         | Home              |
| `/register` | User registration |
| `/login`    | User login        |
| `/vault`    | Password vault    |
| `/add`      | Add a password    |
| `/logout`   | Logout            |

## Technologies

- Backend: Flask
- Database: SQLite
- Password hashing: Argon2id
- Encryption: AES-256-GCM

## Run Locally

```bash
git clone <repository-url>
cd password-manager
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```








