FastAPI To-Do App with MongoDB
This is a simple to-do app built using the FastAPI framework and MongoDB. The app provides CRUD functionality for to-do items, along with user authentication.

Setup
To get started with the project, follow these steps:

Clone the repository to your local machine:
git clone https://github.com/tatavrishi/To_Do_list.git

Navigate to the project directory:
cd fastapi-mongodb-todo

Install the required dependencies using pip
pip install -r requirements.txt

Create a new MongoDB database and collection for the app. Make sure to update the MONGO_URI and MONGO_DB variables in the .env file with the appropriate values.
Start the app using the following command:
uvicorn main:app --reload
This will start the app on http://localhost:8000.

Usage
Once the app is running, you can use the following endpoints to interact with the app:

POST /users/register: Register a new user. Requires a JSON payload with username and password fields.
POST /users/token: Retrieve an authentication token for an existing user. Requires a JSON payload with username and password fields.
GET /items: Retrieve a list of to-do items for the authenticated user.
GET /items/{item_id}: Retrieve a specific to-do item for the authenticated user.
POST /items: Create a new to-do item for the authenticated user. Requires a JSON payload with title and description fields.
PUT /items/{item_id}: Update an existing to-do item for the authenticated user. Requires a JSON payload with title and description fields.
DELETE /items/{item_id}: Delete an existing to-do item for the authenticated user.
All endpoints require a valid authentication token to be included in the Authorization header of the request. The token can be obtained by sending a request to the /users/token endpoint.
