This is a school project for SDEV 300 at UMGC.  

The goal is to build a simple Flask app that features user registration, login, password update, and logout features.  

Usernames and passwords are stored in a database, with the passwords hashed in sha512.

Most routes are hidden until the user logs in.

Failed login attempts are logged with the date, time, and user's IP address.