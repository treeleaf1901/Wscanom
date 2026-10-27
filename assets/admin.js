/**
 * WScanom — scan bertahap (AJAX, batch per batch) supaya tidak timeout
 * di situs dengan banyak file, plus aksi "tandai aman" per baris hasil.
 */
( function () {
	'use strict';

	document.addEventListener( 'DOMContentLoaded', function () {
		var startBtn   = document.getElementById( 'wscanom-start-scan' );
		var progressEl = document.getElementById( 'wscanom-progress' );
		var progressFill = document.querySelector( '.wscanom-progress-fill' );
		var progressText = document.getElementById( 'wscanom-progress-text' );
		var summaryEl  = document.getElementById( 'wscanom-summary' );
		var table      = document.getElementById( 'wscanom-results-table' );
		var tbody      = document.getElementById( 'wscanom-results-body' );

		if ( ! startBtn ) {
			return;
		}

		startBtn.addEventListener( 'click', function () {
			startBtn.disabled = true;
			summaryEl.innerHTML = '';
			tbody.innerHTML = '';
			table.hidden = true;
			progressEl.hidden = false;
			progressText.textContent = WScanomData.strings.listing;
			progressFill.style.width = '0%';

			post( { action: 'wscanom_get_file_list' } )
				.then( function ( res ) {
					if ( ! res.success ) {
						throw new Error( res.data && res.data.message );
					}
					runBatches( res.data.files, res.data.total );
				} )
				.catch( handleError );
		} );

		/**
		 * Jalankan scan per batch sampai seluruh daftar file habis.
		 *
		 * @param {string[]} files Daftar path relatif.
		 * @param {number}   total Jumlah total file.
		 */
		function runBatches( files, total ) {
			var batchSize = WScanomData.batchSize || 75;
			var index = 0;
			var flaggedCount = 0;

			function nextBatch() {
				if ( index >= files.length ) {
					scanRootFiles( flaggedCount );
					return;
				}

				var batch = files.slice( index, index + batchSize );
				index += batch.length;

				progressFill.style.width = Math.round( ( index / total ) * 100 ) + '%';
				progressText.textContent = format( WScanomData.strings.scanning, index, total );

				post( { action: 'wscanom_scan_batch', paths: batch } )
					.then( function ( res ) {
						if ( ! res.success ) {
							throw new Error( res.data && res.data.message );
						}
						res.data.results.forEach( function ( row ) {
							if ( ! row.whitelisted ) {
								flaggedCount++;
							}
							addRow( row );
						} );
						nextBatch();
					} )
					.catch( handleError );
			}

			nextBatch();
		}

		/**
		 * Pindai file sentinel di root (index.php, wp-config.php, dll) setelah
		 * batch wp-content selesai. Daftarnya pendek, jadi cukup satu permintaan.
		 *
		 * @param {number} flaggedCount Jumlah file bermasalah dari tahap sebelumnya.
		 */
		function scanRootFiles( flaggedCount ) {
			progressText.textContent = WScanomData.strings.scanningRoot;

			post( { action: 'wscanom_scan_root' } )
				.then( function ( res ) {
					if ( ! res.success ) {
						throw new Error( res.data && res.data.message );
					}
					res.data.results.forEach( function ( row ) {
						if ( ! row.whitelisted ) {
							flaggedCount++;
						}
						addRow( row );
					} );
					finish( flaggedCount );
				} )
				.catch( handleError );
		}

		/**
		 * Tambahkan satu baris hasil ke tabel, terurut skor tertinggi di atas.
		 *
		 * @param {Object} row Hasil scan satu file.
		 */
		function addRow( row ) {
			table.hidden = false;

			var tr = document.createElement( 'tr' );

			var scoreTd = document.createElement( 'td' );
			var scoreStrong = document.createElement( 'strong' );
			scoreStrong.textContent = row.score;
			scoreStrong.style.color = row.score >= 8 ? '#b32d2e' : '#996800';
			scoreTd.appendChild( scoreStrong );

			var fileTd = document.createElement( 'td' );
			var code = document.createElement( 'code' );
			code.textContent = row.file;
			fileTd.appendChild( code );
			if ( row.whitelisted ) {
				var badge = document.createElement( 'span' );
				badge.className = 'wscanom-badge';
				badge.textContent = WScanomData.strings.whitelisted;
				fileTd.appendChild( document.createTextNode( ' ' ) );
				fileTd.appendChild( badge );
			}

			var findingsTd = document.createElement( 'td' );
			var ul = document.createElement( 'ul' );
			ul.style.margin = '0';
			( row.findings || [] ).forEach( function ( f ) {
				var li = document.createElement( 'li' );
				li.textContent = f;
				ul.appendChild( li );
			} );
			findingsTd.appendChild( ul );

			var actionTd = document.createElement( 'td' );

			if ( row.isRoot ) {
				// File sentinel root (index.php, wp-config.php, dll) tidak bisa
				// dikarantina (dipindah) — situs butuh file itu untuk jalan.
				// Satu-satunya aksi: buang blok tersuntiknya saja, in-place.
				var stripBtn = document.createElement( 'button' );
				stripBtn.type = 'button';
				stripBtn.className = 'button button-small wscanom-btn-danger';
				stripBtn.textContent = WScanomData.strings.stripBlock;
				stripBtn.addEventListener( 'click', function () {
					if ( ! window.confirm( WScanomData.strings.confirmStrip ) ) {
						return;
					}
					stripBtn.disabled = true;
					post( { action: 'wscanom_strip_block', file: row.file } ).then( function ( res ) {
						if ( res.success ) {
							stripBtn.textContent = WScanomData.strings.stripped;
							tr.classList.add( 'wscanom-row-quarantined' );
						} else {
							stripBtn.disabled = false;
							window.alert( ( res.data && res.data.message ) || WScanomData.strings.error );
						}
					} );
				} );
				actionTd.appendChild( stripBtn );
			} else if ( row.hash ) {
				var safeBtn = document.createElement( 'button' );
				safeBtn.type = 'button';
				safeBtn.className = 'button button-small';
				safeBtn.textContent = row.whitelisted ? WScanomData.strings.unmarkSafe : WScanomData.strings.markSafe;
				safeBtn.addEventListener( 'click', function () {
					var action = row.whitelisted ? 'wscanom_whitelist_remove' : 'wscanom_whitelist_add';
					safeBtn.disabled = true;
					post( { action: action, file: row.file, hash: row.hash } ).then( function ( res ) {
						if ( res.success ) {
							row.whitelisted = ! row.whitelisted;
							safeBtn.textContent = row.whitelisted ? WScanomData.strings.unmarkSafe : WScanomData.strings.markSafe;
						}
						safeBtn.disabled = false;
					} );
				} );
				actionTd.appendChild( safeBtn );

				actionTd.appendChild( document.createTextNode( ' ' ) );

				var quarantineBtn = document.createElement( 'button' );
				quarantineBtn.type = 'button';
				quarantineBtn.className = 'button button-small wscanom-btn-danger';
				quarantineBtn.textContent = WScanomData.strings.quarantine;
				quarantineBtn.addEventListener( 'click', function () {
					if ( ! window.confirm( WScanomData.strings.confirmQuarantine ) ) {
						return;
					}
					quarantineBtn.disabled = true;
					safeBtn.disabled = true;
					post( { action: 'wscanom_quarantine_file', file: row.file } ).then( function ( res ) {
						if ( res.success ) {
							quarantineBtn.textContent = WScanomData.strings.quarantined;
							tr.classList.add( 'wscanom-row-quarantined' );
						} else {
							quarantineBtn.disabled = false;
							safeBtn.disabled = false;
							window.alert( ( res.data && res.data.message ) || WScanomData.strings.error );
						}
					} );
				} );
				actionTd.appendChild( quarantineBtn );
			}

			tr.appendChild( scoreTd );
			tr.appendChild( fileTd );
			tr.appendChild( findingsTd );
			tr.appendChild( actionTd );

			// sisipkan terurut skor tertinggi di atas.
			var rows = tbody.querySelectorAll( 'tr' );
			var inserted = false;
			for ( var i = 0; i < rows.length; i++ ) {
				var existingScore = parseInt( rows[ i ].querySelector( 'strong' ).textContent, 10 );
				if ( row.score > existingScore ) {
					tbody.insertBefore( tr, rows[ i ] );
					inserted = true;
					break;
				}
			}
			if ( ! inserted ) {
				tbody.appendChild( tr );
			}
		}

		/**
		 * Tampilkan ringkasan akhir setelah seluruh batch selesai.
		 *
		 * @param {number} flaggedCount Jumlah file yang ditandai (tidak termasuk whitelist).
		 */
		function finish( flaggedCount ) {
			progressEl.hidden = true;
			startBtn.disabled = false;
			summaryEl.textContent = flaggedCount > 0
				? format( WScanomData.strings.done, flaggedCount )
				: WScanomData.strings.doneClean;
		}

		function handleError( err ) {
			progressEl.hidden = true;
			startBtn.disabled = false;
			summaryEl.textContent = WScanomData.strings.error + ( err && err.message ? ' (' + err.message + ')' : '' );
		}

		/**
		 * Kirim permintaan AJAX ke admin-ajax.php dengan nonce plugin ini.
		 *
		 * @param {Object} data Payload tambahan (action, dll).
		 * @return {Promise<Object>}
		 */
		function post( data ) {
			var body = new URLSearchParams();
			body.set( 'nonce', WScanomData.nonce );
			Object.keys( data ).forEach( function ( key ) {
				var value = data[ key ];
				if ( Array.isArray( value ) ) {
					value.forEach( function ( v ) {
						body.append( key + '[]', v );
					} );
				} else {
					body.set( key, value );
				}
			} );

			return fetch( WScanomData.ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body.toString(),
			} ).then( function ( r ) {
				return r.json();
			} );
		}

		/**
		 * sprintf sederhana, cukup untuk %d dan %1$d/%2$d.
		 */
		function format( template ) {
			var args = Array.prototype.slice.call( arguments, 1 );
			var i = 0;
			return template
				.replace( /%(\d+)\$d/g, function ( _, n ) {
					return args[ parseInt( n, 10 ) - 1 ];
				} )
				.replace( /%d/g, function () {
					return args[ i++ ];
				} );
		}
	} );
} )();
