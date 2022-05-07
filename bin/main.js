#! /usr/bin/env node

'use strict';

const fs = require("fs");
const os = require("os");
const path = require("path");
const util = require("util");
const axios = require("axios");
const yargs = require("yargs");
const crypto = require("crypto");
const colors = require("@colors/colors");
const readline = require("readline");
const inquirer = require("inquirer");
const { aws4Interceptor } = require("aws4-axios");
const gql = require('gql-query-builder');

const patterns = {
	access_key_id: /(\'A|"A)(SIA|KIA|IDA|ROA)[JI][A-Z0-9]{14}[AQ][\'"]/g,
	secret_access_key: /[\'"][a-z0-9A-Z+\/]{40}[\'"]/g,

	user_pool_id: /[\'"](us|ap|ca|eu)-(central|east|west|south|northeast|southeast)-(1|2)_[a-zA-Z0-9]{9}[\'"]/g,
	identity_pool_id: /[\'"](us|ap|ca|eu)-(central|east|west|south|northeast|southeast)-(1|2):[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}[\'"]/g,
	hosted_ui: /[\'"]https:\/\/[^ ]+?\/login\?[^ ]*?client_id=[a-z0-9]{26}[^ ]/g,
	cognito_domain: /[\'"]https:\/\/[a-z0-9\-]+\.auth\.(us|ap|ca|eu)-(central|east|west|south|northeast|southeast)-(1|2)\.amazoncognito.com/g,

	appsync_graphql: /[\"']https\:\/\/[a-z0-9]{20,}.appsync-api.(us|ap|ca|eu)-(central|east|west|south|northeast|southeast)-(1|2).amazonaws.com\/graphql[\"']/g,
	graphql_apikey: /[\"']da2-[a-z0-9]{26}[\"']/g
}

yargs
	.usage("Syntax: $0 <command> [options]")
	.command("* <url>", "Check a URL", (yargs) => {
		return yargs.option('interactive', {
			type: 'string',
			description: 'The URL to scan for an AppSync GraphQL endpoint.'
		})
	}, async (argv) => {
		const page = await axios.get(argv.url);

		const gql_endpoint = await retrieveSimpleValue(
			page,
			"appsync_graphql",
			"Which GraphQL endpoint do you want to use?",
			"No AppSync GraphQL endpoint found on the supplied page."
		);

		console.log(`[+] Found AppSync GraphQL Endpoint: ${gql_endpoint}`);

		// Find the auth types. api key > iam creds > cognito.
		const auth_types = [];
		const api_key = await retrieveSimpleValue(
			page,
			"graphql_apikey",
			"Which GraphQL API Key do you want to use?",
			"No AppSync GraphQL endpoint found on the supplied page."
		);

		if (!!api_key) {
			auth_types.push("API Key");
			console.log(`[+] Found API Key: ${api_key}`);
		}

		const access_key_id = await retrieveSimpleValue(
			page,
			"access_key_id",
			"Which Access Key ID do you want to use?",
			"No IAM Access Key ID found on the supplied page."
		);

		if (!!access_key_id) {
			const secret_access_key = await retrieveSimpleValue(
				page,
				"secret_access_key",
				"Which Secret Access Key do you want to use?",
				"No IAM Secret Access Key found on the supplied page."
			);

			if (!!secret_access_key) {
				auth_types.push("AWS IAM Credentials");
				console.log(`[+] Found API Key: ${access_key_id}`);
				console.log(`[+] Found Secret Access Key: ${secret_access_key}`);
			}
		}

		// TODO
		/*const identity_pool_id = await retrieveSimpleValue(
			page,
			"identity_pool_id",
			"No Cognito Identity Pool ID found on the supplied page.",
			"Which Cognito Identity Pool do you want to use?"
		);*/

		if (auth_types.length == 0) {
			console.log('[!] No valid authentication mechanisms were detected.'.red);
			return false;
		}

		const auth_type = await pickValue(auth_types, "Which authentication type do you want to use?");

		console.log(`[+] Authenticating with ${auth_type}...`);

		switch (auth_type) {
			case "API Key":
				await getGqlSchema(gql_endpoint, { "x-api-key": api_key }, false);
				return true;
			break;

			case "AWS IAM Credentials":
				await getGqlSchema(gql_endpoint, {}, { accessKeyId: access_key_id, secretAccessKey: secret_access_key });
				return true;
			break;
		}

		return true;
	})
	.showHelpOnFail(false)
	.help("help")
	.argv;

async function pickValue(values, message) {
	if (values.length < 1) {
		return false
	}

	if (values.length == 1) {
		return values[0];
	}

	const answer = await inquirer.prompt([{
		type: 'list',
		name: 'pick',
		message: `[?] ${message}: `,
		choices: values
	}]);

	return answer.pick;
}

function retrieveSimpleValue(page, pattern, question, none_message) {
	let options = [...page.data.matchAll(patterns[pattern])];
		
	if (options.length < 1) {
		console.log(`[-] ${none_message}`.blue);
		return false;
	}

	options = options.map(e => e[0].replaceAll(/["']/g, ""));
	options = options.filter((e, i) => options.indexOf(e) == i);

	return pickValue(options, question);
}

async function getGqlSchema(endpoint, headers, creds) {
	const cache_dir = path.join(os.homedir(), ".countersync");
	const cache_file = path.join(cache_dir, `${hash(endpoint)}.json`);

	if (!fs.existsSync(cache_dir)) {
		fs.mkdirSync(cache_dir);
	}

	let schema;
	const client = axios.create();

	if (!fs.existsSync(cache_file)) {
		try {
			if (creds) {
				const interceptor = aws4Interceptor({
					region: endpoint.split(".")[2],
					service: "execute-api",
				}, creds);

				client.interceptors.request.use(interceptor);
			}

			schema = await client.post(endpoint, {
				query: "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"
			}, {
				headers
			});

			fs.writeFileSync(cache_file, JSON.stringify(schema.data));
		} catch (e) {
			console.log(e);
			console.log(`[!] Unable to perform the introspection query.`);
			return false;
		}
	}
	
	schema = JSON.parse(fs.readFileSync(cache_file));

	console.log('[+] Successfully retrieved GraphQL Schema.');

	schema = schema.data.__schema;

	const types = schema.types;
	const directives = schema.directives;

	const [query, mutation, subscription] = ["query", "mutation", "subscription"].map(type => {
		if (!!!schema?.[`${type}Type`]?.name) {
			// console.log(`[-] ${type}Type is empty.`.blue);
			return {};
		};

		const result = types
			.filter(e => e.name == schema[`${type}Type`].name)
			.flatMap(e => e.fields.map(f => f.name));
			/*.reduce((acc, cur) => {
				cur.fields.map(e => {
					acc[e.name] = e.args.map(a => {
						return [a.name, a.type.kind == "NON_NULL"]
					});
				})

				return acc;
			}, {});*/

		const length = Object.keys(result).length;

		if (length > 0) {
			console.log(`[*] Found ${length} ${type} action(s)`.green);
		}

		return result;
	});

	await browseGql(schema, endpoint, client, headers);
	return true;
}

async function browseGql(schema, endpoint, client, headers) {

	const types = ["query", "mutation"].filter(e => !!schema[`${e}Type`]?.name); //removed Subscriptions for now.
	const types_with_objects = types
		.filter(type => {
			const obj = schema.types.find(e => e.name == schema[`${type}Type`].name);
			return obj.fields.length > 0
		});

	if (types_with_objects.length == 0) {
		console.log(`[!] Nothing to interact with.`.red);
		return false;
	}

	const type = await pickValue(types_with_objects, "Which object type would you like to browse?");
	const typeObject = schema.types.find(e => e.name == schema[`${type}Type`].name);

	const availableActions = typeObject.fields.map(e => e.name).sort();
	const action = await pickValue(availableActions, "Which action would you like to perform?");
	const actionObject = typeObject.fields.find(e => e.name == action);

	let fields;
	switch (type) {
		case "query":
			const fieldKey = (actionObject.type.name || actionObject.type.ofType.name);
			fields = getFieldsForModel(schema, fieldKey)[fieldKey];
			
			const fieldDepth = countFieldsDepth(fields);
			console.log('');
			console.log(util.inspect(fields, false, null, true));
			console.log(`[*] The schema above represents the data to be requested.`.green);

			if (fieldDepth > 0) {
				console.log(`\n[*] '${action}' has a query field depth of ${fieldDepth}`.green);
				console.log(`[*] It's STRONGLY recommended that you limit the query depth until a single full object is returned.`.green);
				const depth = await trucateDepthInteractively(fields);
				fields = truncateFieldsAtDepth(fields, depth);
			}

			// console.log(util.inspect(fields, false, null, true));
		break;

		case "mutation":
			fields = actionObject.args.map(e => {
				return  (e.type.kind == "NON_NULL") ? e.name : false;
			}).filter(e => !!e);
		break;
	}

	const inputs = actionObject.args.map(e => {
		const required = (e.type.kind == "NON_NULL") ? "!" : "" ;

		return {
			type: 'input',
			name: e.name,
			message: `${e.name}${required}: `
		}
	});

	let variables = {};
	if (inputs.length > 0) {
		console.log(`\n[*] '${action}' has ${inputs.length} parameters. Those appended with '!' are required.`.green);
		variables = await inquirer.prompt(inputs);
		Object.keys(variables).map(e => {
			if (variables[e].length == 0) {
				delete variables[e];
			}

			const thisArg = actionObject.args.find(a => a.name = e);

			const newValue = {
				value: variables[e],
				required: false,
				type: thisArg.type.name
			};

			if (thisArg.type.kind == "NON_NULL") {
				newValue.required = true,
				newValue.type = thisArg.type.ofType.name;
			}

			variables[e] = newValue;
		});

		// console.log(variables);
	}

	const gql_query = gql.query({
		operation: action,
		variables,
		fields
	});

	console.log(`[+] Assembled query:`.blue)
	console.log(gql_query)
	console.log('');

	const result = await client.post(endpoint, gql_query, {
		headers
	});

	if (result.data.errors) {
		console.log(`[!] Got response from AppSync GraphQL:`.red)
		console.log(util.inspect(result.data.errors, false, null, true));
		console.log('');
	} else {
		console.log(`[+] Got response from AppSync GraphQL:`.blue)
		console.log(util.inspect(result.data.data, false, null, true));
		console.log('');
	}

	return browseGql(...arguments);
}

function getFieldsForModel(schema, model, knownModels = []) {
	if (model == null) {
		return null;
	}

	const thisType = schema.types.find(e => e.name == model);

	if (!!!thisType.fields) {
		return model;
	};

	if (knownModels.includes(model)) {
		return null;
	}

	knownModels.push(model);

	return {
		[model]: thisType.fields.map(e => {
			if (["String", "Int", "Float", "Boolean", "ID"].includes(e.type.name)) {
				return e.name;
			}

			if (e.type.name == null && (e.type.kind != "LIST" || !!!e.type.ofType?.name)) {
				return e.name;
			}

			if (e.type.kind == "LIST" && !!e.type.ofType?.name) {
				return getFieldsForModel(schema, e.type.ofType.name, knownModels);
			}

			return getFieldsForModel(schema, e.type.name, knownModels);
		}).filter(e => e !== null)
	}
}

function countFieldsDepth(fields, depth = 0) {

	if (typeof fields != "object") {
		return depth;
	};

	const childObjects = fields.filter(e => {
		// console.log(typeof e, e);
		return (typeof e == "object");
	});
	
	if (childObjects.length == 0) {
		return depth;
	}

	return childObjects
		.map(e => countFieldsDepth(e[Object.keys(e)][0], depth + 1))
		.reduce((acc, cur) => (cur > acc) ? cur : acc, 0);
}

function truncateFieldsAtDepth(fields, depth) {

	if (depth == 0) {
		return null
	}

	return fields.map(e => {
		if (typeof e == "string") {
			return e;
		}

		const key = Object.keys(e)[0];

		if (depth == 1) {
			return null
		}

		return { [key]: truncateFieldsAtDepth(e[key], depth - 1) };
	}).filter(e => e !== null);
}

async function trucateDepthInteractively(fields) {
	const answers = await inquirer.prompt({
		type: 'number',
		name: 'depth',
		validate(value) {
			return (Number.isInteger(value) && value > 0) ? true : "Input must be a positive integer".red;
		},
		default: 2,
		message: "[?] What depth would you like to trucate the fields to?: "
	});

	const tempFields = truncateFieldsAtDepth(fields, answers.depth);
	console.log(util.inspect(tempFields, false, null, true));

	const confirm = await inquirer.prompt({
		type: 'confirm',
		name: 'confirm',
		message: "[?] Is this what you want to send?: ",
		default: false
	});

	return (confirm.confirm) ? answers.depth : trucateDepthInteractively(fields);
}

function hash(what) {
	return crypto.createHash("sha1").update(what).digest("hex");
}