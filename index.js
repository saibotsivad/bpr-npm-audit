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
	'critical',
]

const PROXY_TYPES = {
	local: '127.0.0.1',
	pipe: 'host.docker.internal',
}

const npmSeverityToBitbucketSeverity = {
	info: 'LOW',
	low: 'LOW',
	moderate: 'MEDIUM',
	high: 'HIGH',
	critical: 'HIGH',
}

const bitbucket = {
	branch: process.env.BITBUCKET_BRANCH,
	commit: process.env.BITBUCKET_COMMIT,
	owner: process.env.BITBUCKET_REPO_OWNER,
	slug: process.env.BITBUCKET_REPO_SLUG,
}
if (Object.keys(bitbucket).filter(key => bitbucket[key]).length !== Object.keys(bitbucket).length) {
	console.error('Not all Bitbucket environment variables were set.')
	process.exit(1)
}

const reportName = process.env.BPR_NAME || 'Security: npm audit'
const reportId = process.env.BPR_ID || 'npmaudit'
const proxyHost = PROXY_TYPES[process.env.BPR_PROXY] || PROXY_TYPES.local
const auditLevel = process.env.BPR_LEVEL || 'high'
const auditAnnotationLevel = process.env.BPR_LOG
const maxAuditOutputBufferSize = parseInt(process.env.BPR_MAX_BUFFER_SIZE, 10) || 1024 * 1024 * 10
if (!ORDERED_LEVELS.includes(auditLevel)) {
	console.error('Unsupported audit level.')
	process.exit(1)
}
if (!proxyHost) {
	console.error('Unsupported proxy configuration.')
	process.exit(1)
}
const x = spawnSync('ls', {
	maxBuffer: maxAuditOutputBufferSize,
	encoding: "utf-8"
})
console.log(`directory contents: ${JSON.stringify(x)}`)
const startTime = new Date().getTime()
const { stderr, stdout } = spawnSync('npm', [ 'audit', '--json' ], {
	maxBuffer: maxAuditOutputBufferSize,
})
if (stderr.toString()) {
	console.error('Could not execute the `npm audit` command.', stderr.toString())
	process.exit(1)
}
let audit = stdout.toString()
try {
	audit = JSON.parse(audit)
} catch (error) {
	console.error('Error while parsing `npm audit` output:\n\n' + audit + '\n\n', error)
	process.exit(1)
}
console.log(audit);
const highestLevelIndex = ORDERED_LEVELS.reduce((value, level, index) => {
	return audit.metadata.vulnerabilities[level]
		? index
		: value
}, -1)

const shouldAddAnnotation = severity => {
	if (!auditAnnotationLevel) return true
	return ORDERED_LEVELS.indexOf(severity) >= ORDERED_LEVELS.indexOf(auditAnnotationLevel)
}

const push = (bitbucketUrl, data) => new Promise(resolve => {
	const options = {
		host: proxyHost,
		port: 29418,
		path: bitbucketUrl,
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
	}

	console.log(`options: ${JSON.stringify(options)}`);

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
	reportId,
].join('')

const pushAllReports = async () => {
	console.log(`highestLevelIndex: ${highestLevelIndex}`);
	console.log(`ORDERED_LEVELS: ${ORDERED_LEVELS.indexOf(auditLevel)}`);
	await push(baseUrl, {
		title: reportName,
		details: 'Results of npm audit.',
		report_type: 'SECURITY',
		reporter: bitbucket.owner,
		result: highestLevelIndex < ORDERED_LEVELS.indexOf(auditLevel)
			? 'PASSED'
			: 'FAILED',
		data: [
			{
				title: 'Duration (seconds)',
				type: 'DURATION',
				value: Math.round((new Date().getTime() - startTime) / 1000),
			},
			{
				title: 'Dependencies',
				type: 'NUMBER',
				value: audit.metadata.dependencies.total === undefined
					? audit.metadata.totalDependencies
					: audit.metadata.dependencies.total,
			},
			{
				title: 'Safe to merge?',
				type: 'BOOLEAN',
				value: highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel),
			},
		],
	})

	// npm audit output had a major change here: https://github.com/npm/cli/blob/latest/changelogs/CHANGELOG-7.md#npm-audit
	// I'll still support the old version for now
	if (audit.advisories) {
		for (const [ id, advisory ] of Object.entries(audit.advisories)) {
			if (shouldAddAnnotation(advisory.severity)) {
				let details = advisory.overview + '\n\n' + advisory.recommendation
				if (details.length > MAX_DETAILS_LENGTH) {
					details = details.substring(0, MAX_DETAILS_LENGTH - TRUNCATION_MESSAGE.length) + TRUNCATION_MESSAGE
				}
				await push(
					`${baseUrl}/annotations/${reportId}-${id.replaceAll('/', '-')}`,
					{
						annotation_type: 'VULNERABILITY',
						summary: `${advisory.module_name}: ${advisory.title}`,
						details,
						link: advisory.url,
						severity: npmSeverityToBitbucketSeverity[advisory.severity],
					},
				)
			}
		}
	} else if (audit.vulnerabilities) {
		let annotationCount = 0
		for (const [ id, { via, effects } ] of Object.entries(audit.vulnerabilities)) {

			// These are libs that are effected by a different vulnerability, so we ignore them here.
			if (via && via.length && via.every(v => typeof v === 'string')) continue

			for (const { name, title, url, severity, range } of via) {
				// These are artifacts that I don't understand...
				if (!name || name === 'undefined') continue
				// Possibly ignore lower severity
				if (!shouldAddAnnotation(severity)) continue

				let details = `${name} (${range}) is a ${severity} rated issue "${title}"`
				if (effects && effects.length) {
					details += ' which effects ' + effects
						.map(name => `${name} (${audit.vulnerabilities[name] && audit.vulnerabilities[name].range || '*'})`)
						.join(', ')
				}
				details += '. For more information: ' + url
				if (details.length > MAX_DETAILS_LENGTH) {
					details = details.substring(0, MAX_DETAILS_LENGTH - TRUNCATION_MESSAGE.length) + TRUNCATION_MESSAGE
				}
				// From the Bitbucket API docs: https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D/commit/%7Bcommit%7D/reports/%7BreportId%7D/annotations/%7BannotationId%7D#put
				// "a report can contain up to 1000 annotations"
				// If we get to that many, we'll just quit early.
				annotationCount++
				if (annotationCount >= 1000) continue
				await push(
					`${baseUrl}/annotations/${reportId}-${id.replaceAll('/', '-')}`,
					{
						annotation_type: 'VULNERABILITY',
						summary: `${name}: ${title}`,
						details,
						link: url,
						severity: npmSeverityToBitbucketSeverity[severity],
					},
				)
			}
		}
	}
}

pushAllReports()
	.then(() => {
		console.log('Report successfully pushed to Bitbucket.')
		process.exit(0)
	})
