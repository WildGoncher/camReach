"""
User Management System with Role-Based Access Control.
"""
import os
import bcrypt

# Маппинг пользователей: имя -> {хеш пароля, роль, доступные объекты}
# Роли: "admin", "full", "restricted"
USERS = {
    "pepethefrog": {
        "hash": os.getenv("PASS_PEPETHEFROG"),
        "role": "admin",
        "allowed_objects": None  # Admin видит всё
    },
    "theboss": {
        "hash": os.getenv("PASS_THEBOSS"),
        "role": "full",
        "allowed_objects": None
    },
    "techdir": {
        "hash": os.getenv("PASS_TECHDIR"),
        "role": "full",
        "allowed_objects": None
    },
    "findir": {
        "hash": os.getenv("PASS_FINDIR"),
        "role": "full",
        "allowed_objects": None
    },
    "fullacc1": {
        "hash": os.getenv("PASS_FULLACC1"),
        "role": "full",
        "allowed_objects": None
    },
    "fullacc2": {
        "hash": os.getenv("PASS_FULLACC2"),
        "role": "full",
        "allowed_objects": None
    },
    # Ограниченные пользователи (Restricted)
    "rpizum12": {"hash": os.getenv("PASS_RPIZUM12"), "role": "restricted", "allowed_objects": ["Изумрудная 12А"]},
    "nyizum12": {"hash": os.getenv("PASS_NYIZUM12"), "role": "restricted", "allowed_objects": ["Изумрудная 12А"]},
    
    "rpdol6": {"hash": os.getenv("PASS_RPDOL6"), "role": "restricted", "allowed_objects": ["Долгопрудная 6"]},
    "nydol6": {"hash": os.getenv("PASS_NYDOL6"), "role": "restricted", "allowed_objects": ["Долгопрудная 6"]},
    
    "rpvag9": {"hash": os.getenv("PASS_RPVAG9"), "role": "restricted", "allowed_objects": ["Вагоноремонтная 9/11"]},
    "nyvag9": {"hash": os.getenv("PASS_NYVAG9"), "role": "restricted", "allowed_objects": ["Вагоноремонтная 9/11"]},
    
    "rpdol8": {"hash": os.getenv("PASS_RPDOL8"), "role": "restricted", "allowed_objects": ["Долгопрудная 8"]},
    "nydol8": {"hash": os.getenv("PASS_NYDOL8"), "role": "restricted", "allowed_objects": ["Долгопрудная 8"]},
    
    "rpbud49": {"hash": os.getenv("PASS_RPBUD49"), "role": "restricted", "allowed_objects": ["Буденного 49А"]},
    "nybud49": {"hash": os.getenv("PASS_NYBUD49"), "role": "restricted", "allowed_objects": ["Буденного 49А"]},
    
    "rpizum28": {"hash": os.getenv("PASS_RPIZUM28"), "role": "restricted", "allowed_objects": ["Изумрудная 28А"]},
    "nyizum28": {"hash": os.getenv("PASS_NYIZUM28"), "role": "restricted", "allowed_objects": ["Изумрудная 28А"]},
    
    "rpminus14": {"hash": os.getenv("PASS_RPMINUS14"), "role": "restricted", "allowed_objects": ["Минусинская 14А"]},
    "nyminus14": {"hash": os.getenv("PASS_NYMINUS14"), "role": "restricted", "allowed_objects": ["Минусинская 14А"]},
    
    "rputk44": {"hash": os.getenv("PASS_RPUTK44"), "role": "restricted", "allowed_objects": ["Уткина 44"]},
    "nyutk44": {"hash": os.getenv("PASS_NYUTK44"), "role": "restricted", "allowed_objects": ["Уткина 44"]},
}

def verify_password(username: str, plain_password: str) -> bool:
    """Проверка пароля."""
    user = USERS.get(username)
    if not user or not user.get("hash"):
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            user["hash"].encode("utf-8")
        )
    except Exception:
        return False

def get_user_permissions(username: str) -> dict:
    """Возвращает роль и список доступных объектов."""
    user = USERS.get(username)
    if not user:
        return {"role": "unknown", "allowed_objects": []}
    return {
        "role": user["role"],
        "allowed_objects": user.get("allowed_objects") or []
    }
