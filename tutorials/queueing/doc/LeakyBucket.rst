Leaky Bucket
============

In this step, packets are produced by an active packet source (ActivePacketSource).
The packet source pushes packets into a leaky bucket module, which pushes them into
a passive packet sink (PassivePacketSink).

The network contains ... TODO

.. figure:: media/LeakyBucket.png
   :width: 60%
   :align: center

.. figure:: media/LeakyBucket_Bucket.png
   :width: 65%
   :align: center

**TODO** Config

.. literalinclude:: ../LeakyBucket.ned
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config LeakyBucket
   :end-at: processingTime
   :language: ini
