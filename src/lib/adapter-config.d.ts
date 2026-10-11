// This file extends the AdapterConfig type from "@iobroker/types"

declare global {
    namespace ioBroker {
        interface AdapterConfig {
            host: string;
            username: string;
            password: string;
            useTls: boolean;

            intervalEvents: number;
            intervalPorts: number;
            intervalFirmware: number;
            intervalSettings: number;

            knownIps: string;
            attackThreshold: number;
            alertRemoteLogins: boolean;
            alertNewDevices: boolean;
            skipKnownPrivate: boolean;
            summaryInterval: 'off' | 'daily' | 'weekly';
            confirmations: { id: string; title?: string; ok: boolean }[];
            portSelfTest: boolean;
            vendorFirmwareCheck: boolean;

            telegramEnabled: boolean;
            telegramInstance: string;
            telegramUser: string;
            emailEnabled: boolean;
            emailInstance: string;
            emailTo: string;
            minSeverity: 'info' | 'warning' | 'critical';
            notifyResolved: boolean;
        }
    }
}

export {};
