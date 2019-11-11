
package inet.tutorials.queueing;

import inet.queueing.classifier.WrrClassifier;
import inet.queueing.filter.RedDropper;
import inet.queueing.queue.PacketQueue;
import inet.queueing.scheduler.PriorityScheduler;
import inet.queueing.sink.ActivePacketSink;
import inet.queueing.source.ActivePacketSource;


network RedDropperNetwork
{
    @display("bgb=1250,300");
    submodules:
        producer: ActivePacketSource {
            @display("p=100,100");
        }
        dropper1: RedDropper {
            @display("p=500,100");
        }
        queue1: PacketQueue {
            @display("p=725,100");
        }
        collector: ActivePacketSink {
            @display("p=1150,100");
        }
    connections:
        dropper1.out --> queue1.in;
}
