interface GetTokenParams {
    providerEndpoint: string;
    audience: string;
    repositories: string[];
}
export declare function assumeRole(params: GetTokenParams): Promise<void>;
export {};
