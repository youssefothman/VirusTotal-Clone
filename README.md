# teamC: VirusProtect

## Introduction
Our software is an interface which allows users to search using the hashes of files to determine their maliciousness.
This information is determined by consulting the VirusTotal API as well as from records in our local database.

Our technology stack is comprised of Python/Flask, SQLite, and HTML with Boostrap CSS.

## Installation Instructions
1. Make sure `virtualenv` is installed:

`pip3 install virtualenv`

2. Now, create a new virtual environment for this software:

`mkdir virtual`

`virtualenv virtual`

3. Activate the virtual environment:

`source virtual/bin/activate`

4. Install necessary Python packages:

`pip3 install flask flask_sqlalchemy requests pdfkit`

5. Install the system-wide necessary package (for PDF export):

For MacOS: `brew install homebrew/cask/wkhtmltopdf`

For Debian-based OS: `sudo apt-get install wkhtmltopdf`

For Arch-based OS: `sudo pacman -S wkhtmltopdf`

6. Now, you can run the app:

`flask run`

7. Open the browser and load the address:

`http://localhost:5000`

## Information

Once the flask application is launched you will be taken to the homepage where any string of either characters or numbers, preferably if they are 16 digits long if you are trying to enter an MD5 hash or 32 digits long if you are entering a sha256 hash since that is the length of the hashes in the local database and Virus Total's database.

Once you enter in a hash it will first be used to search through our local database for the hash and returns metadata related to that hash if it is found. If it is not found in the local database, then the application will reach out to Virus Total's database, search through it, and return all the relevant metadata for that hash if it is found. 

If it is not found in either database, then the application returns a message saying that the hash is not malicious and adds it to our local database, then if it gets searched again you will be able to return that message faster. If the hash is found in Virus Total's database, but not our local database, then we add that entry from Virus Total to our local database since it is a malicious hash, pulling all of the relevant information from Virus Total for that entry that our local database takes in.

There is a help page at the top of every HTML web page for helpful tips on what the information on the webiste means and what actions can be performed by the user.

Our website also implements users with a proper log in and log out page so that any user that logs in is able to view any prior searches that they have made, so that they can be looked through quickly and efficiently. The additional feature of our website is our export to PDF button that will take the results of a successful search for a malicious hash and transform the metadata from the search in a downloadable PDF document.

Additional features:
* Export information in a pdf format
* Session Search History
* Local Database for users and history

