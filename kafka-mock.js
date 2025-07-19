class KafkaMock {
    constructor() {
        this.topics = new Map();
        this.consumerGroups = new Map();
        this.offsets = new Map();
    }

    // Create a topic if it doesn't exist
    async createTopic(topic) {
        if (!this.topics.has(topic)) {
            this.topics.set(topic, []);
            this.offsets.set(topic, 0);
        }
    }

    // Produce a message to a topic
    async produce(topic, messages) {
        if (!Array.isArray(messages)) {
            messages = [messages];
        }

        if (!this.topics.has(topic)) {
            await this.createTopic(topic);
        }

        const timestamp = Date.now();
        const newMessages = messages.map((value, index) => ({
            offset: this.offsets.get(topic) + index,
            key: null,
            value: JSON.stringify(value),
            timestamp,
            headers: {}
        }));

        this.topics.get(topic).push(...newMessages);
        this.offsets.set(topic, this.offsets.get(topic) + newMessages.length);

        // Notify consumers if any
        if (this.consumerGroups.has(topic)) {
            const consumers = this.consumerGroups.get(topic);
            for (const { eachMessage } of consumers) {
                for (const message of newMessages) {
                    setImmediate(() => {
                        eachMessage({
                            topic,
                            partition: 0,
                            message: {
                                ...message,
                                value: JSON.parse(message.value)
                            }
                        });
                    });
                }
            }
        }

        return newMessages.map(m => ({
            topicName: topic,
            partition: 0,
            errorCode: 0,
            offset: m.offset.toString(),
            timestamp: m.timestamp
        }));
    }

    // Subscribe to a topic
    async subscribe({ topic, fromBeginning = false, eachMessage }) {
        if (!this.topics.has(topic)) {
            await this.createTopic(topic);
        }

        const consumerId = Math.random().toString(36).substring(7);
        const consumers = this.consumerGroups.get(topic) || [];
        consumers.push({ id: consumerId, eachMessage });
        this.consumerGroups.set(topic, consumers);

        // If fromBeginning, send all existing messages
        if (fromBeginning) {
            const messages = this.topics.get(topic) || [];
            messages.forEach(message => {
                setImmediate(() => {
                    eachMessage({
                        topic,
                        partition: 0,
                        message: {
                            ...message,
                            value: JSON.parse(message.value)
                        }
                    });
                });
            });
        }

        return {
            run: async () => {},
            stop: async () => {
                const consumers = this.consumerGroups.get(topic) || [];
                const filtered = consumers.filter(c => c.id !== consumerId);
                if (filtered.length === 0) {
                    this.consumerGroups.delete(topic);
                } else {
                    this.consumerGroups.set(topic, filtered);
                }
            }
        };
    }

    // Get all messages from a topic (for testing/debugging)
    getMessages(topic) {
        return (this.topics.get(topic) || []).map(m => ({
            ...m,
            value: JSON.parse(m.value)
        }));
    }

    // Clear all topics (for testing)
    clear() {
        this.topics.clear();
        this.consumerGroups.clear();
        this.offsets.clear();
    }
}

// Create a singleton instance
const kafkaMock = new KafkaMock();

// Export a factory function that matches kafkajs API
module.exports = {
    Kafka: class {
        constructor({ brokers, clientId }) {
            this.brokers = brokers;
            this.clientId = clientId;
        }

        admin() {
            return {
                connect: async () => {},
                createTopics: async ({ topics }) => {
                    for (const topic of topics) {
                        await kafkaMock.createTopic(topic.topic);
                    }
                    return true;
                },
                disconnect: async () => {}
            };
        }

        producer() {
            return {
                connect: async () => {},
                disconnect: async () => {},
                send: async ({ topic, messages }) => {
                    return kafkaMock.produce(topic, messages);
                }
            };
        }

        consumer({ groupId }) {
            return {
                connect: async () => {},
                subscribe: ({ topic, fromBeginning }) => {
                    this.topic = topic;
                    this.fromBeginning = fromBeginning;
                    return Promise.resolve();
                },
                run: async ({ eachMessage }) => {
                    if (!this.topic) {
                        throw new Error('Must call subscribe before run');
                    }
                    this.consumer = await kafkaMock.subscribe({
                        topic: this.topic,
                        fromBeginning: this.fromBeginning,
                        eachMessage
                    });
                },
                stop: async () => {
                    if (this.consumer) {
                        await this.consumer.stop();
                    }
                },
                disconnect: async () => {
                    if (this.consumer) {
                        await this.consumer.stop();
                    }
                }
            };
        }
    }
};
