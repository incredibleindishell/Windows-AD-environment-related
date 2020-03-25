
# Extracting username and password hash 

Select name,master.sys.fn_sqlvarbasetostr(password_hash) from master.sys.sql_logins
