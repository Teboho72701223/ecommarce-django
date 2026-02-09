E-Commerce Django Application

This is a Django-based e-commerce web application developed as a capstone project.
The project supports vendor stores, product listings, orders, and user authentication.
It can be run locally using a virtual environment (venv) or using Docker.


Requirements

- Python 3.10+
- Git
- Docker (for containerized setup)
- Virtualenv (optional but recommended)


 1. Running the Project Using Virtual Environment (venv)

Step 1: Clone the Repository

git clone https://github.com/Teboho72701223/ecommarce-django.git
cd ecommarce-django

Step 2: Create and Activate Virtual Environment

python3 -m venv venv
source venv/bin/activate

On Windows:

venv\Scripts\activate

Step 3: Install Dependencies
pip install -r requirements.txt

Step 4: Apply Migrations
python manage.py migrate

Step 5: Create Superuser (Optional)
python manage.py createsuperuser

Step 6: Run Development Server
python manage.py runserver

Open your browser and go to:
http://127.0.0.1:8000/


2. Running the Project Using Docker

Step 1: Build the Docker Image
docker build -t ecommerce .

Step 2: Run the Docker Container
docker run -d -p 8000:8000 --name ecommerce_app ecommerce

Step 3: Apply Migrations in Docker
docker exec -it ecommerce_app python manage.py migrate

Step 4: Access the Application
Open your browser and go to:
http://localhost:8000/


If using Play With Docker, open port 8000 and use the generated link.
