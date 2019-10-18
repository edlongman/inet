Step 5a. Mismatched Parameters between two OSPF neighbor
==================================

Goals
-----

TODO

Configuration
~~~~~~~~~~~~~

R4 and R5 will not establish full adjacency because of mismatch OSPF network type.

This step uses the following network:

.. literalinclude:: ../InterfaceNetworkType.ned
   :start-at: network InterfaceNetworkType
   :language: ned

The configuration in ``omnetpp.ini`` is the following:

.. literalinclude:: ../omnetpp.ini
   :language: ini
   :start-at: Step5a
   :end-before: ------

The OSPF configuration:

.. literalinclude:: ../ASConfig_mismatch.xml
   :language: xml

Results
~~~~~~~

TODO

Sources: TODO

Discussion
----------

Use `this page <https://github.com/inet-framework/inet-tutorials/issues/TODO>`__ in
the GitHub issue tracker for commenting on this tutorial.

