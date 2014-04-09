AD Auth Modules
======

Active Directory Authentication module for wordpress, drupal, and custom sites.

Authenticates users with Identikey Usernames and Passwords with the Active Directory service on campus.

The wordpress plugin automatically adds users who belong to specific groups, as well as assigns permissions
assigned to those groups.

For instance, everyone in the ASSETT-Admins AD group is added to the wordpress database with the permission level of administrators.

-----------------------------------------
INSTALLATION FOR WORDPRESS
-----------------------------------------
Through the backend of wordpress:
1. Download the master-zip from https://github.com/assettcu/adauth/archive/master.zip.
2. Unzip package.
3. Open your wordpress site in a browser and log into the backend.
4. Click on "Plugins"
5. Click on "Add New" right next to the title "Plugins" at the top.
6. Click on "Upload" on the sub-navigation bar below "Install Plugins".
7. Upload the "adauth.zip" file under the "wordpress-plugins" folder from when you unzipped the package.
8. It should automatically install the plugin.

Manually installing the plugin:
1. Download the master-zip from https://github.com/assettcu/adauth/archive/master.zip.
2. Unzip package.
3. Open your wordpress site in a windows explorer (not internet explorer).
4. Navigate to wp-content/plugins and open the folder. You should see all of your site's plugins.
5. Copy the "adauth" folder (not the zip) from the package under the "wordpress-plugin" folder.
6. Paste this into the wp-content/plugins folder.

You will still need to activate the plugin after you've installed it. Either login to the backend and activate it under the plugin's tab or do it manually through the database.
