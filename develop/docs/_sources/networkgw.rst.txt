.. Keysas documentation master file, created by
   sphinx-quickstart on Wed Dec 30 08:13:07 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.


Network gateway (keysas-core)
-----------------------------

By installing Keysas-core alone, you can create an upstream gateway between two separate networks in order to filter files transmitted from the lower network to the upper one.
To do so, use Makefile target **make install-core**. It will prevent the installation of binaries related to USB and webservices. See below to learn about the administration
of **Keysas-core** and how to use it.

.. toctree::
   :maxdepth: 2
   :caption: Contents:
   
   administration
   usage
   download
