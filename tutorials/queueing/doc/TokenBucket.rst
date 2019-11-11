Token Bucket
============

In this step, packets are produced periodically by an active packet source (ActivePacketSource).
The packets are pushed to a token bucket module (TokenBucket). A token generator (TimeBasedTokenGenerator)
generates tokens periodically into the token bucket module. When the token bucket has sufficient
tokens, it emits a packet into a passive packet sink (PassivePacketSink).

The network contains ... TODO

.. figure:: media/TokenBucket.png
   :width: 60%
   :align: center

.. figure:: media/TokenBucket_Bucket.png
   :width: 80%
   :align: center

**TODO** Config

.. literalinclude:: ../TokenBucket.ned
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config TokenBucket
   :end-at: TokenBucketNetwork
   :language: ini
