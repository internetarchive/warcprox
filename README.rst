.. image:: https://travis-ci.org/internetarchive/doublethink.svg?branch=master
    :target: https://travis-ci.org/internetarchive/doublethink

doublethink
============

RethinkDB python library. Provides connection manager and ORM framework
(object-relational mapping, sometimes called ODM or OM for nosql databases).

Connection Manager
------------------

Three main purposes:

- round-robin connections among database servers
- make sure connections close at proper time
- retry retry-able queries on failure

Not currently a connection pool, because it doesn’t keep any connections open.
Should be possible to implement connection pooling without changing the API.
However, testing suggests there would be no appreciable performance gain from
connection pooling.

Usage Example
~~~~~~~~~~~~~

::

    import doublethink
    rr = doublethink.Rethinker(['db0.foo.com', 'db0.foo.com:38015', 'db1.foo.com'], 'my_db')
    rr.table('mytable').insert({'foo':'bar','baz':2}).run()
    for result in rr.table('mytable'):
        print("result={}".format(result))

ORM
---

Simple yet powerful ORM system. *Does not enforce a schema.*

Usage Example
~~~~~~~~~~~~~

::

    import doublethink

    rr = doublethink.Rethinker(['db0.foo.com', 'db0.foo.com:38015', 'db1.foo.com'], 'my_db')

    class MyTable(doublethink.Document):
        pass
    MyTable.table_create(rr)

    doc1 = MyTable(rr, {'animal': 'elephant', 'size': 'large'})
    doc1.save()

    doc1_copy = MyTable.load(rr, doc1.id)
    doc1_copy.food = 'bread'
    doc1_copy.save()

    doc1.first_name = 'Frankworth'
    doc1.save()

    doc1.refresh()

Service Registry
----------------

Now also has a ServiceRegistry class, a lightweight solution for service
discovery for distributed services. Maintains service info and status in
a rethinkdb table called “services”.

