import test from "node:test";
import assert from "node:assert/strict";
import { normalizeDevice, evaluateConnection, classifyObservation } from "./network-guardian.mjs";
const mac = "aa:bb:cc:dd:ee:ff";
test("unknown devices are denied", () => assert.equal(evaluateConnection([], {mac}).reason, "unknown-device"));
test("TV lockdown denies approved domains too", () => assert.equal(evaluateConnection([{mac,mode:"lockdown",destinations:["stream.example"]}], {mac,destination:"stream.example"}).decision, "deny"));
test("isolated devices cannot reach internet", () => assert.equal(evaluateConnection([{mac,mode:"isolated"}], {mac,destination:"example.com"}).decision, "deny"));
test("approved devices only reach exact allowlisted destination", () => {
 const devices=[{mac,mode:"approved",destinations:["stream.example"]}];
 assert.equal(evaluateConnection(devices,{mac,destination:"stream.example"}).decision,"allow");
 assert.equal(evaluateConnection(devices,{mac,destination:"evil.stream.example"}).decision,"deny");
});
test("reject malformed device", () => assert.throws(()=>normalizeDevice({mac:"invalid"})));
test("radio detection is not surveillance evidence", () => assert.equal(classifyObservation({type:"radio"}).status,"unattributed"));
test("only confirmed gateway decisions are verified", () => {
 assert.equal(classifyObservation({type:"firewall",action:"deny"}).status,"unverified");
 assert.equal(classifyObservation({type:"firewall",action:"deny",enforced:true}).status,"verified");
});
