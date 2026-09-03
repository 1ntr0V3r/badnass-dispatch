import secrets

secret_key = secrets.token_hex(32)
aes_key = secrets.token_hex(32)
mock_secret = secrets.token_hex(16)

env_lines = [
    "APP_ENV=production",
    "APP_PORT=8000",
    f"SECRET_KEY={secret_key}",
    "JWT_ALGORITHM=HS256",
    "POSTGRES_USER=badnass_admin",
    "POSTGRES_PASSWORD=badnass_secure_pass_2026",
    "POSTGRES_DB=badnass_dispatch",
    "POSTGRES_HOST=postgres",
    "POSTGRES_PORT=5432",
    "REDIS_HOST=redis",
    "REDIS_PORT=6379",
    f"AES_256_KEY_HEX={aes_key}",
    f"MOCK_CLIENT_SECRET={mock_secret}",
]

with open(".env", "w") as f:
    f.write("\n".join(env_lines) + "\n")

env_example_lines = [
    "APP_ENV=production",
    "APP_PORT=8000",
    "SECRET_KEY=<generate with: python -c 'import secrets; print(secrets.token_hex(32))'>",
    "JWT_ALGORITHM=HS256",
    "POSTGRES_USER=badnass_admin",
    "POSTGRES_PASSWORD=<strong_password_here>",
    "POSTGRES_DB=badnass_dispatch",
    "POSTGRES_HOST=postgres",
    "POSTGRES_PORT=5432",
    "REDIS_HOST=redis",
    "REDIS_PORT=6379",
    "AES_256_KEY_HEX=<generate with: python -c 'import secrets; print(secrets.token_hex(32))'>",
    "MOCK_CLIENT_SECRET=<generate with: python -c 'import secrets; print(secrets.token_hex(16))'>",
]

with open(".env.example", "w") as f:
    f.write("\n".join(env_example_lines) + "\n")

print("Env files written successfully")
print(f"SECRET_KEY length: {len(secret_key)} chars")
print(f"AES_256_KEY_HEX length: {len(aes_key)} chars")
