<script lang="ts">
	import { onMount } from 'svelte';
	import { Check, Copy, ExternalLink, FileText, RefreshCw, Trash2, Upload } from '@lucide/svelte';
	import { api, type MediaObject } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';
	import { isImage, mediaDetails, sortNewestFirst } from '$lib/media';

	let media = $state<MediaObject[]>([]);
	let loading = $state(true);
	let loadError = $state('');
	let error = $state('');
	let success = $state('');
	let deleting = $state<string | null>(null);
	let copied = $state<string | null>(null);

	async function loadMedia() {
		loading = true;
		loadError = '';
		const result = await api.getMedia();
		loading = false;
		if (result.ok) {
			media = sortNewestFirst(result.data ?? []);
		} else {
			loadError = result.message || 'Could not load media. Please try again.';
		}
	}

	async function deleteMedia(item: MediaObject) {
		if (
			!confirm(
				`Permanently delete "${item.name}"? Emails that already use it will show a broken image.`
			)
		) {
			return;
		}
		deleting = item.name;
		const result = await api.deleteMedia(item.name);
		deleting = null;
		if (result.ok) {
			media = media.filter((existing) => existing.name !== item.name);
			success = `${item.name} deleted.`;
			error = '';
		} else {
			error = result.message || `Could not delete ${item.name}.`;
			success = '';
		}
	}

	async function copyUrl(item: MediaObject) {
		try {
			await navigator.clipboard.writeText(item.url);
			copied = item.url;
			setTimeout(() => {
				if (copied === item.url) copied = null;
			}, 2000);
		} catch {
			error = 'Could not copy the URL to the clipboard.';
			success = '';
		}
	}

	onMount(loadMedia);
</script>

<div class="py-8">
	<div class="flex flex-wrap items-start justify-between gap-4">
		<div>
			<h1 class="text-3xl font-bold text-gray-900">Media</h1>
			<p class="mt-1 text-gray-600">
				Images available to use in emails. Media is shared between all users.
			</p>
		</div>
		<div class="flex items-center gap-2">
			<button
				type="button"
				onclick={loadMedia}
				disabled={loading}
				class="inline-flex cursor-pointer items-center gap-2 rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
			>
				<RefreshCw class="h-4 w-4" />
				Refresh
			</button>
			<a
				href="/uploadImage"
				class="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
			>
				<Upload class="h-4 w-4" />
				Upload
			</a>
		</div>
	</div>

	<div class="mt-5 space-y-3">
		<Feedback {error} {success} />
	</div>

	{#if loading}
		<div class="mt-6 flex flex-col items-center justify-center py-12 text-gray-500">
			<div
				class="h-8 w-8 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600"
			></div>
			<p class="mt-3 text-sm" role="status">Loading media…</p>
		</div>
	{:else if loadError}
		<div class="mt-6">
			<Feedback error={loadError} />
			<button
				type="button"
				onclick={loadMedia}
				class="mt-3 text-sm font-medium text-blue-600 underline">Retry</button
			>
		</div>
	{:else if media.length === 0}
		<div
			class="mt-6 rounded-lg border border-dashed border-gray-300 bg-white px-6 py-12 text-center"
		>
			<p class="text-gray-600">No media has been uploaded yet.</p>
			<a href="/uploadImage" class="mt-2 inline-block text-sm font-medium text-blue-600 underline"
				>Upload an image</a
			>
		</div>
	{:else}
		<p class="mt-6 text-sm text-gray-500">
			{media.length} item{media.length === 1 ? '' : 's'}
		</p>
		<ul class="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
			{#each media as item (item.url)}
				<li class="flex flex-col overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
					<a
						href={item.url}
						target="_blank"
						rel="noopener noreferrer"
						class="block aspect-video bg-gray-50"
						aria-label={`Open ${item.name}`}
					>
						{#if isImage(item)}
							<img src={item.url} alt="" loading="lazy" class="h-full w-full object-cover" />
						{:else}
							<div class="flex h-full w-full items-center justify-center text-gray-400">
								<FileText class="h-10 w-10" />
							</div>
						{/if}
					</a>
					<div class="flex flex-1 flex-col gap-3 p-3">
						<div class="min-w-0">
							<p class="truncate text-sm font-medium text-gray-900" title={item.name}>
								{item.name}
							</p>
							<p class="text-xs text-gray-500">{mediaDetails(item)}</p>
						</div>
						<div class="mt-auto flex items-center justify-between gap-2">
							<div class="flex items-center gap-1">
								<button
									type="button"
									onclick={() => copyUrl(item)}
									aria-label={`Copy URL for ${item.name}`}
									title="Copy URL"
									class="cursor-pointer rounded-md border border-gray-300 p-2 text-gray-600 hover:bg-gray-50"
								>
									{#if copied === item.url}
										<Check class="h-4 w-4 text-green-600" />
									{:else}
										<Copy class="h-4 w-4" />
									{/if}
								</button>
								<a
									href={item.url}
									target="_blank"
									rel="noopener noreferrer"
									aria-label={`Open ${item.name} in a new tab`}
									title="Open"
									class="rounded-md border border-gray-300 p-2 text-gray-600 hover:bg-gray-50"
								>
									<ExternalLink class="h-4 w-4" />
								</a>
							</div>
							<button
								type="button"
								onclick={() => deleteMedia(item)}
								disabled={deleting !== null}
								aria-label={`Delete ${item.name}`}
								class="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-red-300 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50"
							>
								<Trash2 class="h-4 w-4" />
								{deleting === item.name ? 'Deleting…' : 'Delete'}
							</button>
						</div>
					</div>
				</li>
			{/each}
		</ul>
	{/if}
</div>
