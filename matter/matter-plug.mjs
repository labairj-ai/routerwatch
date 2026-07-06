import "@matter/nodejs-ble";
import { Environment, ServerNode, Seconds } from "@matter/main";

const [, , command, arg] = process.argv;
const pairingCode = process.env.MATTER_PAIRING_CODE;
const passcode = Number(process.env.MATTER_PASSCODE);
const shortDiscriminator = Number(process.env.MATTER_SHORT_DISCRIMINATOR);
const nodeId = "linkind-router-plug";

async function main() {
  Environment.default.vars.set("log.level", process.env.MATTER_LOG_LEVEL || "warn");
  Environment.default.vars.set("ble.enable", true);

  const node = await ServerNode.create({
    id: "routerwatch-controller",
    commissioning: {
      enabled: false,
    },
    network: { port: 0, ble: false },
    productDescription: {
      name: "RouterWatch Controller",
      deviceType: 0x0016,
    },
    basicInformation: {
      vendorName: "RouterWatch",
      vendorId: 0xfff1,
      productName: "RouterWatch Controller",
      productId: 0x8001,
      nodeLabel: "RouterWatch Controller",
    },
    controller: {
      fabricLabel: "routerwatch",
      ble: true,
    },
  });

  await node.start();

  try {
    if (command === "commission") {
      if (!pairingCode || !Number.isInteger(passcode) || !Number.isInteger(shortDiscriminator)) {
        throw new Error(
          "Commissioning requires MATTER_PAIRING_CODE, MATTER_PASSCODE, and MATTER_SHORT_DISCRIMINATOR.",
        );
      }
      console.log(`Commissioning ${nodeId} with pairing code ${pairingCode.replace(/.(?=.{4})/g, "*")}`);
      const discoveryOptions = {
        id: nodeId,
        passcode,
        timeout: Seconds(180),
        discoveryCapabilities: { ble: true, onIpNetwork: true },
      };
      if (process.env.MATTER_UNFILTERED !== "1") {
        discoveryOptions.shortDiscriminator = shortDiscriminator;
      }
      const wifiSsid = process.env.MATTER_WIFI_SSID;
      const wifiCredentials = process.env.MATTER_WIFI_PASSWORD;
      if (wifiSsid && wifiCredentials) {
        discoveryOptions.wifiNetwork = { wifiSsid, wifiCredentials };
        console.log(`Provisioning Wi-Fi SSID ${wifiSsid}`);
      }
      const discovery = node.peers.commission({
        ...discoveryOptions,
      });
      const peer = await discovery;
      console.log(`Commissioned ${peer.id}`);
      await printPeer(peer);
      return;
    }

    const peer = node.peers.get(nodeId) || [...node.peers][0];
    if (!peer) {
      throw new Error("No commissioned peers found. Run: node matter-plug.mjs commission");
    }

    await peer.start();

    if (command === "info" || !command) {
      await printPeer(peer);
      return;
    }

    if (!["on", "off", "toggle"].includes(command)) {
      throw new Error("Usage: node matter-plug.mjs commission|info|on|off|toggle");
    }

    await runOnOff(peer, command);
    console.log(`Sent ${command} to ${peer.id}`);
  } finally {
    await node.close();
  }
}

async function printPeer(peer) {
  console.log(`Peer id: ${peer.id}`);
  console.log(`Peer lifecycle commissioned: ${peer.lifecycle.isCommissioned}`);
  console.log("Endpoints:");
  for (const endpoint of peer.parts) {
    const endpointId = endpoint.id ?? endpoint.number ?? "unknown";
    const supported = endpoint.behaviors?.supported;
    const behaviors = supported
      ? Object.keys(supported).sort().join(",")
      : "available after endpoint start";
    console.log(`- ${endpointId}: ${behaviors}`);
  }
}

async function runOnOff(peer, action) {
  let didSend = false;
  for (const endpoint of peer.parts) {
    if (!endpoint.behaviors?.supported?.onOff) continue;
    await endpoint.act(async agent => {
      if (action === "on") await agent.onOff.on();
      if (action === "off") await agent.onOff.off();
      if (action === "toggle") await agent.onOff.toggle();
      didSend = true;
    });
    if (didSend) return;
  }
  throw new Error("No OnOff cluster found on commissioned peer.");
}

main().catch(error => {
  console.error(error?.stack || error);
  process.exit(1);
});
