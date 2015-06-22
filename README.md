# Sports Catalog

The Mountain Sports catalog is a web app based on Flask and SQLAlchemy which
lists and categorizes typical items of popular mountain sports. It supports
user logins which enables content editing and provides APIs for JSON and XML.
For a mobile-friendly experience, the whole design is based on Bootstrap.

## Quick Start

1. Clone this repo.
2. Get the Vagrantfile from the [fullstack-nanodegree-vm repository] (https://github.com/udacity/fullstack-nanodegree-vm).
3. Install and run a Vagrant VM with the Vagrantfile.
4. Configure the home directory of your VM to be able to run the Tournament Planner code.
5. Create the database by calling `database_setup.py`.
6. Pre-fill the database with some example data by calling `fill_database.py`.
7. Run the app with `application.py`.

## Documentation

The main page lists the most recently added items and provides access to the
sports categories (via sidebar), the APIs for JSON and XML as well as the login
section (both via header).
* The main section as well as the category section - reached by clicking on a
  specific category via the sidebar - show a preview of each item. A click on
  `View details` shows the full description of the item.
* A click on `Login` leads to the login section where users can log into the
  catalog app via OAuth with their Google+ or Facebook accounts. After logging
  in, new buttons will appear in the category and item sections which allow
  them to edit and delete existing items or to create new ones.
* The `API` button gives access to XML and JSON endpoints. Both provide the
  complete content of the item database.

## Creator

**Philip Taferner**

- [Google+] (https://plus.google.com/u/0/+PhilipTaferner/posts)
- [Github] (https://github.com/ctaf)
