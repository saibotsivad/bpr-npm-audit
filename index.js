#!/usr/bin/env node

const { spawnSync } = require('child_process')

const ORDERED_LEVELS = [
	'info',
	'low',
	'moderate',
	'high',
	'critical'
]

const PROXY_TYPES = {
	local: 'http://localhost:29418',
	pipe: 'http://host.docker.internal:29418'
}

const bitbucket = {
	branch: process.env.BITBUCKET_BRANCH,
	commit: process.env.BITBUCKET_COMMIT,
	build: process.env.BITBUCKET_BUILD_NUMBER,
	owner: process.env.BITBUCKET_REPO_OWNER,
	slug: process.env.BITBUCKET_REPO_SLUG
}
if (Object.keys(bitbucket).filter(key => bitbucket[key]).length !== Object.keys(bitbucket).length) {
	console.error('Not all Bitbucket environment variables were set.')
	process.exit(1)
}

const reportName = process.env.BPR_NAME || 'Security: npm audit'
const reportId = process.env.BPR_ID || 'npmaudit'
const proxyUrl = PROXY_TYPES[process.env.BPR_PROXY || 'local']
const auditLevel = process.env.BPR_LEVEL || 'high'
if (!ORDERED_LEVELS.includes(auditLevel)) {
	console.error('Unsupported audit level.')
	process.exit(1)
}
if (!proxyUrl) {
	console.error('Unsupported proxy configuration.')
	process.exit(1)
}

const startTime = new Date().getTime()
const { stderr, stdout } = spawnSync('npm', [ 'audit', '--json' ])
if (stderr.toString()) {
	console.error('Could not execute the `npm audit` command.', stderr.toString())
	process.exit(1)
}
const audit = JSON.parse(stdout.toString())

const highestLevelIndex = ORDERED_LEVELS.reduce((value, level, index) => {
	return audit.metadata.vulnerabilities[level]
		? index
		: value
}, -1)

const report = {
	title: reportName,
	details: 'Results of npm audit.',
	report_type: 'SECURITY',
	reporter: bitbucket.owner,
	result: highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel)
		? 'FAILED'
		: 'PASSED',
	data: [
		{
			title: 'Duration (seconds)',
			type: 'DURATION',
			value: Math.round((new Date().getTime() - startTime) / 1000)
		},
		{
			title: 'Dependencies',
			type: 'NUMBER',
			value: audit.metadata.dependencies
		},
		{
			title: 'Safe to merge?',
			type: 'BOOLEAN',
			value: highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel)
		}
	]
}

const url = [
	'http://api.bitbucket.org/2.0/repositories/',
	bitbucket.owner,
	'/',
	bitbucket.slug,
	'/commit/',
	bitbucket.commit,
	'/reports/',
	reportName
].join('')

const response = spawnSync('curl', [
	'--proxy', proxyUrl,
	'--request', 'PUT',
	url,
	'--header', 'Content-Type: application/json',
	'--data-raw', `'${JSON.stringify(report)}'`
])

if (response.stderr.toString()) {
	console.error('Could not push report to Bitbucket.', url, response.stderr.toString())
	process.exit(1)
} else {
	console.log('Report pushed to Bitbucket.')
	process.exit(0)
}
