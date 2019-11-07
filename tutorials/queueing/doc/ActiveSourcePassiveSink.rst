Active Source Passive Sink
==========================

In this test, packets are produced periodically by an active packet source
(ActivePacketSource). The packets are consumed by a passive packet sink
(PassivePacketSink).

The network contains ... TODO

.. figure:: media/ActiveSourcePassiveSink.png
   :width: 50%
   :align: center

**TODO** Config

.. literalinclude:: ../ActiveSourcePassiveSink.ned
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config ActiveSourcePassiveSink
   :end-at: productionInterval
   :language: ini
