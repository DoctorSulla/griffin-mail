<script lang="ts">
	import { onMount } from 'svelte';
	import { Upload, Image as ImageIcon, X } from '@lucide/svelte';
	import { api, type S3UploadDetails } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let uploadDetails = $state<S3UploadDetails | null>(null);
	let loading = $state(true);
	let error = $state('');

	let fileInput = $state<HTMLInputElement | null>(null);
	let selectedFile = $state<File | null>(null);
	let previewUrl = $state<string | null>(null);
	let isDragging = $state(false);
	let hasContentTypeField = $derived(
		uploadDetails
			? Object.keys(uploadDetails.post_fields).some((key) => key.toLowerCase() === 'content-type')
			: false
	);

	async function loadUploadForm() {
		loading = true;
		error = '';
		const result = await api.getS3UploadDetails();
		loading = false;

		if (result.ok && result.data) {
			uploadDetails = result.data;
		} else {
			error = result.message || 'Failed to load upload configuration.';
		}
	}

	function setSelectedFile(file: File | null) {
		if (previewUrl) {
			URL.revokeObjectURL(previewUrl);
			previewUrl = null;
		}

		selectedFile = file;
		if (file && file.type.startsWith('image/')) {
			previewUrl = URL.createObjectURL(file);
		}
	}

	function handleFileChange(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		setSelectedFile(input.files?.[0] ?? null);
	}

	function handleDrop(event: DragEvent) {
		event.preventDefault();
		isDragging = false;

		const file = event.dataTransfer?.files?.[0] ?? null;
		if (!file || !fileInput) return;

		const dataTransfer = new DataTransfer();
		dataTransfer.items.add(file);
		fileInput.files = dataTransfer.files;
		setSelectedFile(file);
	}

	function clearFile() {
		if (fileInput) {
			fileInput.value = '';
		}
		setSelectedFile(null);
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	}

	onMount(() => {
		loadUploadForm();
		return () => {
			if (previewUrl) {
				URL.revokeObjectURL(previewUrl);
			}
		};
	});
</script>

<div class="mx-auto max-w-2xl py-8">
	<h1 class="text-3xl font-bold text-gray-900">Upload image</h1>
	<p class="mt-1 text-gray-600">Select or drag and drop an image file to upload.</p>

	<div class="mt-6 rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
		{#if loading}
			<div class="flex flex-col items-center justify-center py-12 text-gray-500">
				<div
					class="h-8 w-8 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600"
				></div>
				<p class="mt-3 text-sm">Preparing upload…</p>
			</div>
		{:else if error}
			<Feedback {error} />
		{:else if uploadDetails}
			<form
				method="POST"
				action={uploadDetails.upload_url}
				enctype="multipart/form-data"
				class="space-y-5"
			>
				{#each Object.entries(uploadDetails.post_fields) as [key, value]}
					<input type="hidden" name={key} {value} />
				{/each}
				{#if !hasContentTypeField}
					<input type="hidden" name="Content-Type" value={selectedFile?.type ?? ''} />
				{/if}

				<div>
					<label
						for="image-upload"
						ondragover={(e) => {
							e.preventDefault();
							isDragging = true;
						}}
						ondragleave={() => {
							isDragging = false;
						}}
						ondrop={handleDrop}
						class="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors {isDragging
							? 'border-blue-500 bg-blue-50'
							: 'border-gray-300 bg-gray-50/50 hover:border-blue-400 hover:bg-blue-50/40'}"
					>
						<div
							class="flex h-12 w-12 items-center justify-center rounded-full bg-blue-100 text-blue-600"
						>
							<Upload class="h-6 w-6" />
						</div>
						<p class="mt-3 text-sm font-medium text-gray-900">
							<span class="text-blue-600">Click to upload</span> or drag and drop
						</p>
						<p class="mt-1 text-xs text-gray-500">PNG, JPG, GIF, or WebP</p>
						<input
							bind:this={fileInput}
							id="image-upload"
							type="file"
							name="file"
							accept="image/*"
							required
							onchange={handleFileChange}
							class="sr-only"
						/>
					</label>
				</div>

				{#if selectedFile}
					<div
						class="flex items-center justify-between gap-4 rounded-lg border border-gray-200 bg-gray-50 p-3"
					>
						<div class="flex min-w-0 items-center gap-3">
							{#if previewUrl}
								<img
									src={previewUrl}
									alt="Selected preview"
									class="h-14 w-14 shrink-0 rounded-md border border-gray-200 object-cover"
								/>
							{:else}
								<div
									class="flex h-14 w-14 shrink-0 items-center justify-center rounded-md border border-gray-200 bg-white text-gray-400"
								>
									<ImageIcon class="h-6 w-6" />
								</div>
							{/if}
							<div class="min-w-0">
								<p class="truncate text-sm font-medium text-gray-900">{selectedFile.name}</p>
								<p class="text-xs text-gray-500">{formatBytes(selectedFile.size)}</p>
							</div>
						</div>
						<button
							type="button"
							onclick={clearFile}
							aria-label="Remove selected file"
							class="cursor-pointer rounded-md p-1.5 text-gray-400 transition-colors hover:bg-gray-200 hover:text-gray-600"
						>
							<X class="h-4 w-4" />
						</button>
					</div>
				{/if}

				<div class="flex items-center justify-end gap-3 pt-1">
					{#if selectedFile}
						<button
							type="button"
							onclick={clearFile}
							class="cursor-pointer rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
						>
							Clear
						</button>
					{/if}
					<button
						type="submit"
						disabled={!selectedFile}
						class="cursor-pointer rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
					>
						Upload image
					</button>
				</div>
			</form>
		{/if}
	</div>
</div>
