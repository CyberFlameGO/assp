This should be a short whitepaper to configure and use ASSP with any supported database.
This whitepaper assumes, that you have the needed knowledge about databases and there management!

To use other databases then MySQL, to have import-,backup- and export functions and to use databases for the penaltybox and
spamdb you need a ASSP version 1.3.6 or above! There has to be a file assp_db_import.cfg in ASSP root directory!!!!

requirements:

- a database / tablespace whith index/key support (like MySQL,Pg,Oracle,MSSQL,Informix,DB2 and others)
- a databaseuser with read/write and Create/Alter-Table permission
- perl Tie::RDBM module (from CPAN or PPM) - all also required modules will be also installed by default
- perl DBD::(your database) driver - you can see the installed drivers in the Webinterface-section "File Path and Database"
  under DBdriver. If you can not find a perl driver for your database, you can also use ODBC or ADO - if your OS supports that.

NOTICE:

ASSP requires permanent opened connections to the database listener. If you set a maximum allowed concurrent connections
in your DB engine configuration, the value should be at least 800!
If you set a timeout parameter in your DB engine configuration, this value should be at lest 5 minutes!


configuration:

you have to define:

- myhost:
The host (name or ip address) to connect to the database. Some database drivers do not need this parameter - but it must be
already set.

- DBdriver: 
The database driver used to access your database - DBD-driver. The following drivers are available on your system:
ADO|AnyData|CSV|DBM|ExampleP|File|Gofer|Mock|ODBC|Oracle|Proxy|SQLRelay|SQLite|SQLite2|Sponge|mysql|mysqlPP
If you can not find the driver for your database in this list, you should install it via cpan or ppm!
- or if you have installed an ODBC-driver for your database and DBD-ODBC, just create a DSN and use ODBC.
Usefull are ADO|DB2|Informix|ODBC|Oracle|Pg|Sybase|mysql|mysqlPP - but any other SQL compatible database should also work.

syntax examples: driver,option1,option2,...,...
ADO,[DSN=mydsn]
DB2
Informix
ODBC,DSN=mydsn|driver={SQL Server},Server=server_name
Oracle,SID=1|INSTANCE_NAME=myinstance|SERVER=myserver|SERVICE_NAME=myservice_name,[PORT=myport]
Pg,[PORT=myport]
Sybase,SERVER=myserver,[PORT=myport]
mysql,[PORT=myport]
mysqlPP,[PORT=myport]

The options and there possible or required order depending on the used DBD-driver, please read the drivers documentation, if you do not
know the needed option. The username, password, host and databasename are always used from this configuration page. 

- mydb:
This database must exist before starting ASSP, necessary tables will be created automatically into this database.

- myuser:
  the database user
- mypassword:
  the password of the database user

There are more parameters to set, but this parameters have default values and they are descripted in the configuration screen!

Now define a value "DB:" for all lists and caches you want to use a database table for 
(whitelist,delaydb,pbdb,spamdb,redlist).
You do not need to use all of them, you have the choice to select!

If you are here - go back to the top and verify all your settings!

This is a good time to restart ASSP - you have to do this any time, you have changed any database related parameters listed
above!
How ever - ASSP should now be ready to work. If you have made an upgrade form an earlyer version, you can import your old
files in to the database. To do this, there are two ways: you can use the ImportMysqlDB-option in the webinterface and import
will be done by ASSP every time it starts and it finds a import-file in the import-directory.
You need to configure "importDBDir" and you have to copy all files you want to import in to this directory. Now rename this
files to *.add or *.rpl what ever you want ASSP to do - an ADD or a REPLACE records in to the database.

Files can be:
- pbdb.black.db.(add|rpl)
- pbdb.mxa.db.(add|rpl)
- pbdb.ptr.db(add|rpl)
- pbdb.rbl.db.(add|rpl)
- pbdb.rwl.db.(add|rpl)
- pbdb.spf.db.(add|rpl)
- pbdb.uribl.db.(add|rpl)
- pbdb.white.db.(add|rpl)
- redlist.(add|rpl)
- whitelist.(add|rpl)
- spamdb.(add|rpl)
- spamdb.helo.(add|rpl)
- delaydb.(add|rpl)
- delaydb.white.(add|rpl)
Use the extension "add" or "rpl" to add or replace the records to the tables.
Only files for database-enabled tables will be imported "pbdb|spamdb|redlist|whitelist|delaydb"! 

At this time all functions of ASSP are well tested with MySQL(ODBC/direct),MSSQL(ODBC/ADO) and Oracle(ODBC/direct),
but it should work with any other database, as long as you have a perl driver for that. Only if you want to use the
import function with you database, you may get DBI errors. In this case the file assp_db_import.cfg should be modified
for your database. Please change ASSP in to debug mode, stop ASSP, rename the maillog.txt,
prepaire the import directory and start ASSP. Please send the following informations to ASSP group:
database type and version - and the maillog.txt with the errors.
If you have some knowledge in SQL you can try to add a section for your database to the assp_db_import.cfg file!

If you want to replicate databases between several ASSP installations, you have to make sure that the replication processes ignoring duplicate records. 
For MySQL you have to add the following line in to my.ini:

slave-skip-errors=1582 1062 1051

If you use any replication mechanism with Microsoft SQL Server:

- Add the attribute 'ROWGUIDCOL' to the column PKEY of each table that should be replicated, before you start replication, 
because some MSSQL versions will create an extra identity column with that attribute, which will lead in to database errors in ASSP. 
The replication attributes/constraints have been changed by MS from version to version - please read the documentation for your MSSQL Server.
- Set 'preventBulkImport' to on - otherwise the import procedure of ASSP will destroy replication attributes/constraints of the DB tables. 
If you want to use the BulkImport, you must edit the file 'assp_db_import.cfg' by changing the statements for 
'drop primary key' and 'add primary key' according to the requirements of your SQL server version.




