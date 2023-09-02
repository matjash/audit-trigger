Audit trigger for postgres. Fork from [this repo](https://github.com/2ndQuadrant/audit-trigger) including a bunch of changes:

* converted from hstore to jsonb
* Add a function to stop auditing a table.
* Added option to not track insert statements.
* remove unused variables
* add pk to the table schema
