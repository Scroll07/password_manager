

from pas_app.core.password_tool import PasswordTool
from pas_app.schemas.passwords import Password


def test__init(password_tool):
    assert password_tool.vault_data is not None
    assert password_tool.username is not None
    assert password_tool.vault_name is not None

def test__add(password_tool):
    password_tool.add(
        service="service",
        username='username',
        password="password",
        note='note'
    )
    passwrods = password_tool.vault_data.user_passwords
    assert len(passwrods) == 1
    pas = passwrods[0]
    assert pas.service == 'service'
    assert pas.username == 'username'
    assert pas.password == 'password'
    assert pas.note == 'note'
    
def test__get_all_passwords(password_tool):
    for _ in range(3):
        password_tool.add(
            service="service",
            username='username',
            password="password",
            note='note'
        )
    passwrods = password_tool.vault_data.user_passwords
    assert len(passwrods) == 3
    

def test__get_all_passwords__empty(password_tool):
    passwords = password_tool.get_all_passwords()
    assert len(passwords) == 0
    
     
def test__get_one_password__empty(password_tool):
    password = password_tool.get_one_password(service="No service")
    assert password == None

def test__get_one_password__ok(password_tool):
    password_tool.add(
            service="service",
            username='username',
            password="password",
            note='note'
        )
    password = password_tool.get_one_password(service="service")
    assert password is not None
    assert password.service == 'service'
    assert password.username == 'username'
    assert password.password == 'password'
    assert password.note == 'note'


def test__get_passwords_by_service(password_tool):
    for i in range(3):
        password_tool.add(
            service=f"service-{i}",
            username='username',
            password="password",
            note='note'
        )
    password_tool.add(
        service="wrong_service",
        username='username',
        password="password",
        note='note'
    )
    passwords = password_tool.get_passwords_by_service(service="service")
    assert len(passwords) == 3
    
def test__edit(password_tool):
    password_tool.add(
        service="service",
        username='username',
        password="password",
        note='note'
    )
    changed_password = password_tool.edit(service="service", note='', password="ADMIN")
    password = password_tool.vault_data.user_passwords[0]
    assert password.service == "service"
    assert password.username == 'username'
    assert password.password == 'ADMIN'
    assert password.note == ''
    assert changed_password == password
    
def test__delete(password_tool):
    password_tool.add(
        service="service",
        username='username',
        password="password",
        note='note'
    )
    assert len(password_tool.vault_data.user_passwords) == 1
    password_tool.delete(service="service")
    assert len(password_tool.vault_data.user_passwords) == 0
    