import type * as core from "@actions/core";
import { jest } from "@jest/globals";

export const error = jest.fn<typeof core.error>();
export const getIDToken = jest.fn<typeof core.getIDToken>();
export const getInput = jest.fn<typeof core.getInput>();
export const info = jest.fn<typeof core.info>();
export const saveState = jest.fn<typeof core.saveState>();
export const setFailed = jest.fn<typeof core.setFailed>();
export const setOutput = jest.fn<typeof core.setOutput>();
export const setSecret = jest.fn<typeof core.setSecret>();
export const warning = jest.fn<typeof core.warning>();
