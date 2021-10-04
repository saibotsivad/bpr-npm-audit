#!/usr/bin/env node

const { spawnSync } = require('child_process')
const { request } = require('http')

const MAX_DETAILS_LENGTH = 2000
const TRUNCATION_MESSAGE = '[...]'

const ORDERED_LEVELS = [
	'info',
	'low',
	'moderate',
	'high',
	'critical'
]

const PROXY_TYPES = {
	local: 'localhost',
	pipe: 'host.docker.internal'
}

const npmSeverityToBitbucketSeverity = {
	info: 'LOW',
	low: 'LOW',
	moderate: 'MEDIUM',
	high: 'HIGH',
	critical: 'CRITICAL'
}

const bitbucket = {
	branch: process.env.BITBUCKET_BRANCH,
	commit: process.env.BITBUCKET_COMMIT,
	owner: process.env.BITBUCKET_REPO_OWNER,
	slug: process.env.BITBUCKET_REPO_SLUG
}
if (Object.keys(bitbucket).filter(key => bitbucket[key]).length !== Object.keys(bitbucket).length) {
	console.error('Not all Bitbucket environment variables were set.')
	process.exit(1)
}

const reportName = process.env.BPR_NAME || 'Security: npm audit'
const reportId = process.env.BPR_ID || 'npmaudit'
const proxyHost = PROXY_TYPES[process.env.BPR_PROXY || 'local']
const auditLevel = process.env.BPR_LEVEL || 'high'
const maxAuditOutputBufferSize = parseInt(process.env.BPR_MAX_BUFFER_SIZE, 10) || 1024 * 1024 * 10
if (!ORDERED_LEVELS.includes(auditLevel)) {
	console.error('Unsupported audit level.')
	process.exit(1)
}
if (!proxyHost) {
	console.error('Unsupported proxy configuration.')
	process.exit(1)
}

const startTime = new Date().getTime()
const { stderr, stdout } = spawnSync('npm', [ 'audit', '--json' ], {
	maxBuffer: maxAuditOutputBufferSize
})
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

const push = (bitbucketUrl, data) => new Promise((resolve, reject) => {
	const options = {
		host: proxyHost,
		port: 29418,
		path: bitbucketUrl,
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' }
	}
	const req = request(options, response => {
		let body = ''
		response.setEncoding('utf8')
		response.on('data', chunk => {
			body += chunk.toString()
		})
		response.on('end', () => {
			if (response.statusCode !== 200) {
				console.error('Could not push report to Bitbucket.', response.statusCode, body)
				process.exit(1)
			} else {
				resolve()
			}
		})
	})
	req.write(JSON.stringify(data))
	req.end()
})

const baseUrl = [
	'https://api.bitbucket.org/2.0/repositories/',
	bitbucket.owner,
	'/',
	bitbucket.slug,
	'/commit/',
	bitbucket.commit,
	'/reports/',
	reportId
].join('')

const pushAllReports = async () => {
	await push(baseUrl, {
		title: reportName,
		details: 'Results of npm audit.',
		report_type: 'SECURITY',
		reporter: bitbucket.owner,
		result: highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel)
			? 'PASSED'
			: 'FAILED',
		data: [
			{
				title: 'Duration (seconds)',
				type: 'DURATION',
				value: Math.round((new Date().getTime() - startTime) / 1000)
			},
			{
				title: 'Dependencies',
				type: 'NUMBER',
				value: audit.metadata.dependencies.total === undefined
                    ? audit.metadata.totalDependencies
                    : audit.metadata.dependencies.total
			},
			{
				title: 'Safe to merge?',
				type: 'BOOLEAN',
				value: highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel)
			}
		]
	})

	for (const [ id, advisory ] of Object.entries(audit.advisories)) {
		let details = advisory.overview + '\n\n' + advisory.recommendation
		if (details.length > MAX_DETAILS_LENGTH) {
			details = details.substring(0, MAX_DETAILS_LENGTH - TRUNCATION_MESSAGE.length) + TRUNCATION_MESSAGE
		}
		await push(
			`${baseUrl}/annotations/${reportId}-${id}`,
			{
				annotation_type: 'VULNERABILITY',
				summary: `${advisory.module_name}: ${advisory.title}`,
				details,
				link: advisory.url,
				severity: npmSeverityToBitbucketSeverity[advisory.severity]
			}
		)
	}
}

pushAllReports()
	.then(() => {
		console.log('Report successfully pushed to Bitbucket.')
		process.exit(0)
	})
