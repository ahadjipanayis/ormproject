class MetasploitRouter:
    def db_for_read(self, model, **hints):
        # Αν το table είναι 'hosts' ή 'services' (ή αν app_label == 'metasploit_integration'), επιστρέφουμε 'metasploit'
        if model._meta.db_table in ['hosts', 'services', 'vulns', 'loot']:
            return 'metasploit'
        return None

    def db_for_write(self, model, **hints):
        if model._meta.db_table in ['hosts', 'services', 'vulns', 'loot']:
            return 'metasploit'
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # Αποτρέπουμε migrations για το Metasploit DB
        if db == 'metasploit':
            return False
        return None

def allow_relation(self, obj1, obj2, **hints):
    db_set = {'metasploit'}
    if obj1._state.db in db_set and obj2._state.db in db_set:
        return True
    return None
