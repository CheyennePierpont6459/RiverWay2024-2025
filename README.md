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

    Create a `.env` file in the project root (optional) and set the following variables: 

    ```env 

    SECRET_KEY=your_secret_key 

    MYSQL_HOST=localhost 

    MYSQL_USER=root 

    MYSQL_PASSWORD=your_mysql_password 

    MYSQL_DB=ccc_emergency_map 

    ``` 

    Alternatively, set these variables in your system environment. 

5. **Set Up the Database** 

    - **Create Database and Tables** 

        Execute your provided MySQL SQL script to create the `ccc_emergency_map` database and all tables. 

        ```bash 

        mysql -u root -p your_mysql_password < ccc_emergency_map_schema.sql 

        ``` 

    - **Initialize Database Migrations** 

        ```bash 

        flask db init 

        flask db migrate -m "Initial migration." 

        flask db upgrade 

        ``` 

6. **Run the Application** 

    ```bash 

    flask run 

    ``` 

    The application will be accessible at `http://localhost:5000/`. 

## Usage 

1. **Registration** 

    - Users can register as Customers via the registration page. 

    - Super Admins can create Admin and Super Admin accounts through the Super Admin dashboard. 

2. **Login** 

    - Navigate to the login page and enter your credentials. 

    - Upon successful login, you'll be redirected to your respective dashboard based on your role. 

3. **Dashboards** 

    - **Customer Dashboard**: View trips, create distress alerts, view site details, and leave reviews. 

    - **Employee Dashboard**: Manage trips, handle assigned alerts, view all distress trips, view site details, and view customer reviews. 

    - **Admin Dashboard**: Create Employee accounts, view trips, manage site details, and override assignments. 

    - **Super Admin Dashboard**: Create and manage Admin and Super Admin accounts, and manage site details. 

## Security Considerations 

- **Password Handling**: Passwords are hashed using Werkzeug's security utilities. 

- **Environment Variables**: Sensitive information like secret keys and database passwords should be set as environment variables and not hardcoded. 

- **Role-Based Access**: Decorators ensure that users can only access functionalities permitted to their roles. 

## Contributing 

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes. 

## License 

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. 
