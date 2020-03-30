# Howto reproduce

```
~ mkdir target
~ javac src/JDKSSLSessionContextReproducer.java -d target/
~ java -cp src:target JDKSSLSessionContextReproducer
```

This will produce something like this:

```
Exception in thread "main" java.lang.AssertionError: context must not be null
	at JDKSSLSessionContextReproducer.assertSession(JDKSSLSessionContextReproducer.java:62)
	at JDKSSLSessionContextReproducer.main(JDKSSLSessionContextReproducer.java:53)
```
