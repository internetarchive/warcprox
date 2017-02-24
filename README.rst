.. image:: https://travis-ci.org/nlevitt/rethinkstuff.svg?branch=master
    :target: https://travis-ci.org/nlevitt/rethinkstuff

rethinkstuff
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

Usage Example
~~~~~~~~~~~~~

::

    import rethinkstuff
    r = rethinkstuff.Rethinker(['db0.foo.com', 'db0.foo.com:38015', 'db1.foo.com'], 'my_db')
    r.table('mytable').insert({'foo':'bar','baz':2}).run()
    for result in r.table('mytable'):
        print("result={}".format(result))

ORM
---

Simple yet powerful ORM system. *Does not enforce a schema.*

Usage Example
~~~~~~~~~~~~~

::

    import rethinkstuff

    r = rethinkstuff.Rethinker(['db0.foo.com', 'db0.foo.com:38015', 'db1.foo.com'], 'my_db')

    class MyTable(rethinkstuff.Document):
        pass
    MyTable.table_create()

    doc1 = MyTable(r, {'animal': 'elephant', 'size': 'large'})
    doc1.save()

    doc1_copy = MyTable.get(r, doc1.id)
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

