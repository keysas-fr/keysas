******
Usage
******


From the untrusted network
==========================

After installation is done, you will have to create at least one *untrusted* user account as we do not create a default one during the installation process.
You can create a new account with the following command line :

.. code-block:: shell-session

 $ sudo adduser  --home /var/local/in --gid [KEYSAS-IN_GID] untrusted-user

Where *KEYSAS-IN_GID* is the ID of the group keysas-in.

In order to avoid keysas-in daemon to be running under root privileges, we take advantage of the rsync binary.

.. warning::

 For security reasons, sending directories or any kind of archives is not allowed. If doing so, it will be deleted ! 

To upload a single file :

.. code-block:: shell-session

 $ rsync -e ssh --chmod=ug=rw /path/MyFile.docx  untrusted-user@untrusted-ip:

To send every files in a directory:

.. code-block:: shell-session

 $ rsync -r -e ssh --chmod=ug=rw /path/MyFolder/*  untrusted-user@untrusted-ip:

.. hint::

 For more convenience, you should of course add an alias to your favorite shell's configuration.
 For exemple:

 .. code-block:: bash

   # ~/.bashrc
   alias sendfiles="rsync -r -e ssh --chmod=ug=rw"

From the trusted network
=========================

As for *untrusted* users, you also need to create new *trusted* users belonging to the group **keysas-out** to be able to retrieve files from /var/local/out/

.. code-block:: shell-session

 $ sudo adduser  --home /var/local/out --gid [KEYSAS-OUT_GID] trusted-user 

Where *KEYSAS-OUT_GID* is the ID of the group keysas-out.

Your *trusted* user will now be able to connect with ssh to get the files back and remove them manually.

