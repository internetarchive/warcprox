# pyrethink
Rudimentary rethinkdb python library with some smarts (and maybe some dumbs)

## What? Why?

As of now there is a very small amount of code here. I had three projects using the Rethinker class, and had enough code churn inside the class that it became too painful to keep the three copies in sync. Thus, a library shared among them.

Three main purposes:
- round-robin connections among database servers
- make sure connections close at proper time
- retry retry-able queries on failure

Not really a connection pool, because it doesn't keep any connections open, but it does take care of connection management.

## Usage
```
import rethinkdb as r
import pyrethink

rr = pyrethink.Rethinker(['db0.foo.com', 'db0.foo.com:38015', 'db1.foo.com'], 'my_db')

rr.run(r.table('my_table').insert({'foo':'bar','baz':2}))

for result in rr.results_iter(r.table('my_table')):
    print("result={}".format(result))
```
