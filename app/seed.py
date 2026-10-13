
"""Начальное заполнение базы данных."""

from app.database import SessionLocal
from app.models import Group, Permission, Role, Subject, User, Grade
from app.security import hash_password


PERMISSIONS = {
    "read_grades": "Перегляд оцінок",
    "edit_grades": "Редагування оцінок",
    "read_schedule": "Перегляд розкладу",
    "manage_users": "Управління користувачами",
    "manage_groups": "Управління групами",
    "manage_subjects": "Управління дисциплінами",
    "view_reports": "Перегляд звітів",
}

ROLE_MATRIX = {
    "admin": list(PERMISSIONS),
    "teacher": [
        "read_grades",
        "edit_grades",
        "read_schedule",
        "view_reports",
    ],
    "student": ["read_grades", "read_schedule"],
}


def seed():
    db = SessionLocal()

    try:
        # Не создаём данные повторно, если заполнение уже выполнялось.
        if db.query(Role).first():
            print("Database already seeded.")
            return

        # Создаём разрешения.
        perms = {
            name: Permission(name=name, description=description)
            for name, description in PERMISSIONS.items()
        }
        db.add_all(perms.values())
        db.flush()

        # Создаём роли и связываем их с разрешениями.
        roles = {}

        for role_name, permission_names in ROLE_MATRIX.items():
            role = Role(name=role_name)
            role.permissions = [perms[name] for name in permission_names]
            roles[role_name] = role

        db.add_all(roles.values())

        # Создаём учебную группу и дисциплину.
        group = Group(
            name="КН-31",
            department="Комп'ютерні науки",
            year=3,
        )

        subject = Subject(
            name="Безпека інформаційних систем",
            credits=4.0,
            semester=5,
        )

        db.add_all([group, subject])
        db.flush()

        # Создаём пользователей. Пароли сохраняются только в виде хешей.
        admin = User(
            username="admin",
            email="admin@university.edu",
            full_name="Адміністратор Системи",
            password_hash=hash_password("Admin123!@#"),
        )
        admin.roles.append(roles["admin"])

        teacher = User(
            username="teacher01",
            email="teacher@university.edu",
            full_name="Іваненко Петро Миколайович",
            password_hash=hash_password("Teacher123!"),
        )
        teacher.roles.append(roles["teacher"])

        student = User(
            username="student01",
            email="student@university.edu",
            full_name="Петренко Марія Олексіївна",
            password_hash=hash_password("Student123!"),
            group_id=group.id,
        )
        student.roles.append(roles["student"])

        db.add_all([admin, teacher, student])
        db.flush()

        # Добавляем тестовую оценку студента.
        db.add(
            Grade(
                student_id=student.id,
                subject_id=subject.id,
                grade=92,
                assigned_by=teacher.id,
            )
        )

        db.commit()

        print("Seed completed successfully!")
        print(f"Roles: {db.query(Role).count()}")
        print(f"Permissions: {db.query(Permission).count()}")
        print(f"Users: {db.query(User).count()}")

    except Exception as error:
        db.rollback()
        print(f"Seed failed: {error}")
        raise

    finally:
        db.close()


if __name__ == "__main__":
    seed()
