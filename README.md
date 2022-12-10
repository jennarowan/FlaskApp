This is a school project for SDEV 300 at UMGC.  

The goal is to build a simple Flask app that features user registration, login, and logout features.  

Usernames and passwords are stored in a text file instead of a more secure form of storage per the assignment instructions.  Even though a text file is used, passwords are appropriately hashed in sha512 for security purposes.

Most routes are hidden until the user logs in.

Failed login attempts will be logged.
