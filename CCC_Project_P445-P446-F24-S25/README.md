The owner has asked that we make them an app.
It will have a digital map that they have created of the river on it as well as safety information. 
Every year they get more phone calls of paddlers being confused and scared and needing directions or in some cases emergency services. 
The customers will be able to click a button and enter there approximate or precise location that will be sent to CCC. 
It also can be forwarded to emergency services If needed. Making getting to them faster, safer, and less time consuming.
This is the map that Cave Country Canoes has kindly provided us and will be used inside the app

![CCCRiverMap24-WPhotos](https://github.com/user-attachments/assets/ab598f57-71a4-4994-bcfb-62147c696194)

![Untitled design (14)](https://github.com/user-attachments/assets/a7845a40-f220-4ad3-8e5b-47bf9313c4f9)


# CCC Emergency Map System 

## Overview 

The CCC Emergency Map System is a Flask-based web application designed to manage emergency trips, distress alerts, and user feedback. It supports multiple user roles, including Customers, Employees, Admins, and Super Admins, each with specific permissions and functionalities. 

## Features 

- **User Authentication**: Secure registration and login for all user types. 

- **Role-Based Access Control**: Different dashboards and functionalities based on user roles. 

- **Trip Management**: Employees and Admins can create and manage trips. 

- **Emergency Distress Alerts**: Customers can create distress alerts, which Employees can manage. 

- **Site Details Management**: Admins and Super Admins can view and update site details. 

- **User Management**: Super Admins can create and manage Admin and Super Admin accounts. 

- **Customer Feedback**: Customers can leave reviews and ratings for trips. 

## Installation 

### Prerequisites 

- Python 3.x 

- MySQL Server 

### Steps 

1. **Clone the Repository** 

    ```bash 

    git clone https://github.com/yourusername/ccc_emergency_map.git 

    cd ccc_emergency_map 

    ``` 

2. **Set Up Virtual Environment** 

    ```bash 

    python3 -m venv venv 

    source venv/bin/activate  # On Windows use `venv\Scripts\activate` 

    ``` 

3. **Install Dependencies** 

    ```bash 

    pip install -r requirements.txt 

    ``` 

4. **Configure Environment Variables** 

    Create a `.env` file in the project root and set the following variables: 

    ```env 

    SECRET_KEY=your_secret_key 

    MYSQL_HOST=localhost 

    MYSQL_USER=root 

    MYSQL_PASSWORD=your_mysql_password 

    MYSQL_DB=ccc_emergency_map 
   
   MAIL_USERNAME=cccemergencyresponse@gmail.com
   MAIL_PASSWORD=<cccemergencyresponse@gmail.com's google account app password> #get from Google Account manager
   MAIL_PORT=465

   ROOT_PASSWORD=SuperSecretAdminPassword #consider a more secure Root password
    ``` 

    Alternatively, set these variables in your system environment. 
5. **Run the following in the terminal to generate a SECRET_KEY for the .env file.**
```bash
python -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8'))"
```
   Replace the SECRET_KEY=<your_secret_key> with that command output.


6. **Set Up the Database** 

    - **Create Database and Tables** 

        Execute your provided MySQL SQL script to create the `ccc_emergency_map` database and all tables. 

        ```bash 

        mysql -u root -p your_mysql_password < ccc_emergency_map_schema.sql 

        ``` 

    - **Initialize Database Migrations** 
   
    - Change directory to ~/CCC_Project_P445-P446-F24-S25

        ```bash
      python -m flask db init
      
      python -m flask db stamp head
      
      python -m flask db migrate -m "<description>"
      
      python -m flask db upgrade

        ``` 

7. **Run the Application** 

    ```bash 

    python -m flask run 

    ``` 

    The application will be accessible at `http://localhost:5000/` or on the localnetwork at http://192.168.X.X:5000 depending on socket capability.

## Usage 

1. **Registration** 

    - Users can register as Customers via the registration page.
    - Admins can create other Admin accounts through the Admin dashboard if they elevate permissions to a Super Admin.
    - Employee accounts are handled by Admins and Super Admins. 
    - The first admin must be created through the /admin_setup route. It is assumed that whomever does this can be elevated to a Super Admin because the admin root password is needed to setup the first admin. In the example .env the admin root password is "SuperSecretAdminPassword". 

2. **Login** 

    - Navigate to the login page and enter your credentials. 

    - Upon successful login, you'll be redirected to your respective dashboard based on your role. 

3. **Dashboards** 

    - **Customer Dashboard**: 
      - View trips
      - Create distress alerts
      - View site details
      - Leave reviews. 

    - **Employee Dashboard**: 
      - Manage trips
      - handle assigned alerts
      - view all distress trips
      - View site details
      - View customer reviews. 

    - **Admin Dashboard**: 
      - Create, delete, and modify details of Employee accounts
      - Manage assignments for emergencies. 
      - Chat

    - **Super Admin Dashboard** (Extension of Admin Dashboard):
      - Do everything an Admin can
      - Create, delete, and modify details of Admin accounts
      - Lock an account
      - Manage chat and chat themselves
      - See logs

## Security Considerations 

- **Password Handling**: Passwords are hashed using Werkzeug's security utilities. 

- **Environment Variables**: Sensitive information like secret keys and database passwords should be set as environment variables and not hardcoded. 

- **Role-Based Access**: Decorators ensure that users can only access functionalities permitted to their roles. 
- Admins who are capable in elevating themselves to a Super Admin will have access to the Google Account (cccemergencyresponse@gmail.com) login credentials, knowledge of the App password, and database root password. 

## Contributing 

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes. 

## License 

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. 
