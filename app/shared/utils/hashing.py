import bcrypt


def hash_password(password: str|None) -> str|None:
    if not password:
        return None
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")

